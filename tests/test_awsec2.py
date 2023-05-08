"""Mock tests for awssec2"""
from time import time

import pytest

from virtualdesktopspawner.awsec2 import Ec2SsmInstance, get_endpoint


def test_get_endpoint(aws_session):
    assert get_endpoint("ec2", "region") == "http://localhost:4566"
    assert get_endpoint("ssm", "region") == "http://localhost:4566"


# Can't use fixtures in parametrize, need to lookup with request
# https://engineeringfordatascience.com/posts/pytest_fixtures_with_parameterize/
@pytest.mark.parametrize("vpc", ["default_vpc", "aws_vpc"])
@pytest.mark.asyncio
async def test_create_delete(aws_session, instance_name, create_args, request, vpc):
    vpc_id, subnet_id = request.getfixturevalue(vpc)

    esi = Ec2SsmInstance(aws_session, instance_name, subnet_id=subnet_id)
    assert await esi.get_instance() is None

    instance = await esi.create(**create_args)
    assert instance["ImageId"] == "ami-id"
    assert instance["InstanceType"] == "instance.type"
    assert instance["InstanceId"] == esi.id
    instance_id = instance["InstanceId"]

    with pytest.raises(Exception) as exc:
        await esi.create(**create_args)
    assert exc.value.args[0].startswith(f"Instance already created: {instance_name}")

    assert esi._get_vpcid() == vpc_id

    sg = esi._get_security_group(f"ec2-{instance_name}", vpc_id)
    assert sg
    assert sg["GroupName"] == f"ec2-{instance_name}"
    assert sg["VpcId"] == vpc_id

    expected_ingress = {
        "FromPort": 11111,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "10.1.2.3/8"}],
        "ToPort": 22222,
    }
    expected_egress = {
        "FromPort": 33333,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "192.168.1.2/24"}],
        "ToPort": 44444,
    }

    assert len(sg["IpPermissions"]) == 1
    for k, v in expected_ingress.items():
        assert sg["IpPermissions"][0][k] == v

    assert len(sg["IpPermissionsEgress"]) == 1
    for k, v in expected_egress.items():
        assert sg["IpPermissionsEgress"][0][k] == v

    assert await esi.delete() is not None
    assert esi.ec2.describe_instance_status(InstanceIds=[instance_id])[
        "InstanceStatuses"
    ][0]["InstanceState"]["Name"] in ("shutting-down", "terminated")

    assert not esi._get_security_group(f"ec2-{instance_name}", vpc_id)


def test_wait(aws_session, instance_name):
    class Timer:
        def __init__(self, delay):
            self.start = time()
            self.stop = self.start + delay
            self.pings = []

        def ping(self, elapsed):
            now = time()
            offset = now - self.start
            assert offset - elapsed < 0.5
            if now > self.stop:
                return True
            self.pings.append(offset)

    esi = Ec2SsmInstance(aws_session, instance_name)

    t1 = Timer(1.5)
    esi._wait(t1.ping, poll_interval=1, max_wait=3)
    assert len(t1.pings) == 1

    t2 = Timer(1.5)
    esi._wait(t2.ping, initial_delay=0, poll_interval=1, max_wait=3)
    assert len(t2.pings) == 2

    t3 = Timer(3)
    with pytest.raises(RuntimeError) as exc:
        esi._wait(t3.ping, poll_interval=1, max_wait=1.5, timeout_message="timeout")
    assert exc.value.args[0] == "timeout"


@pytest.mark.asyncio
async def test_start_stop(aws_session, instance_name, create_args):
    esi = Ec2SsmInstance(aws_session, instance_name)

    with pytest.raises(RuntimeError) as exc:
        await esi.start()
    assert exc.value.args[0] == f"Instance not found: {instance_name}"
    with pytest.raises(RuntimeError):
        await esi.stop()
    assert exc.value.args[0] == f"Instance not found: {instance_name}"

    assert await esi.create(**create_args) is not None
    assert (await esi.get_instance())["State"]["Name"] in ("pending", "running")

    # Already running, but should be fine to call again
    assert await esi.start()

    # Doesn't do anything since localstack goes straight to running
    r = await esi.wait_instance("running")
    assert r["State"]["Name"] == "running"
    assert await esi.stop()
    assert (await esi.get_instance())["State"]["Name"] in ("stopping", "stopped")

    assert await esi.delete()


@pytest.mark.asyncio
async def test_state_wait(aws_session, instance_name, create_args):
    esi = Ec2SsmInstance(aws_session, instance_name)
    assert await esi.create(**create_args) is not None

    with pytest.raises(RuntimeError) as exc:
        await esi.wait_instance("stopped")
    assert (
        exc.value.args[0]
        == f"Instance {esi.id} is not in any of states ['stopping', 'stopped']: running"
    )

    with pytest.raises(RuntimeError) as exc:
        await esi.wait_instance("terminated")
    assert exc.value.args[0] == (
        f"Instance {esi.id} is not in any of states "
        "['shutting-down', 'terminated']: running"
    )

    await esi.wait_instance("running")
    await esi.stop()

    with pytest.raises(RuntimeError) as exc:
        await esi.wait_instance("running")
    assert exc.value.args[0] == (
        f"Instance {esi.id} is not in any of states ['pending', 'rebooting']: stopped"
    )

    assert await esi.delete()


@pytest.mark.asyncio
@pytest.mark.parametrize("windows", [True, False])
async def test_ssm(aws_session, instance_name, create_args, windows):
    esi = Ec2SsmInstance(aws_session, instance_name, windows=windows)

    assert await esi.create(**create_args)

    # Not implemented in localstack:
    # assert esi.wait_ssm_online()

    r = await esi.ssm_commands(["test"])
    assert r["InstanceId"] == esi.id
    if windows:
        assert r["DocumentName"] == "AWS-RunPowerShellScript"
    else:
        assert r["DocumentName"] == "AWS-RunShellScript"

    assert await esi.delete()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "owner,name,arch,ami_id,exists",
    [
        ("amazon", "Windows_Server-*", "x86_64", None, True),
        ("amazon", "al2022-ami-*", "arm64", None, True),
        ("amazon", "al2022-ami-*", "arm64", "ami-*", True),
        ("amazon", "al2022-ami-*", "arm64", "ami-nonexistent", False),
        ("000000000000", "al2022-ami-*", "arm64", None, False),
    ],
)
async def test_find_ami(aws_session, instance_name, owner, name, arch, ami_id, exists):
    esi = Ec2SsmInstance(aws_session, instance_name)
    kwargs = {"owner": owner, "name": name, "architecture": arch}
    if ami_id:
        kwargs["image-id"] = ami_id
    image = await esi.find_ami(**kwargs)

    assert bool(image) == exists
    if exists:
        assert image["ImageOwnerAlias"] == owner
        assert image["Name"].startswith(name.rstrip("*"))
        assert image["Architecture"] == arch
