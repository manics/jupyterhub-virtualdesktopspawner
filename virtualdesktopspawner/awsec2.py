#!/usr/bin/env python
# coding: utf-8

import asyncio
import functools
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING
from typing import Any as AnyT
from typing import Awaitable as AwaitableT
from typing import Callable as CallableT
from typing import Dict as DictT
from typing import List as ListT
from typing import Optional as OptionalT
from typing import Tuple as TupleT
from typing import Union as UnionT

import boto3
import botocore.loaders
import botocore.regions

try:
    from mypy_boto3_ec2.client import EC2Client
except ImportError:
    if TYPE_CHECKING:
        raise

JsonT = DictT[str, AnyT]


async def run_background_process(
    cmd: str,
    args: ListT[str],
    env: OptionalT[DictT[str, str]] = None,
) -> TupleT[asyncio.subprocess.Process, asyncio.Task[tuple[bytes, bytes]]]:
    """
    Run a process in the background.

    returns: Tuple: (process, communicate)
    """
    process = await asyncio.create_subprocess_exec(
        cmd,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    communicate = asyncio.create_task(process.communicate())
    return process, communicate


def run_in_executor(_func: CallableT) -> CallableT:
    """
    Decorator to run a class method in a thread.
    Class must have a `thread_pool` attribute.
    """

    @functools.wraps(_func)
    def wrapped(self, *args, **kwargs):
        loop = asyncio.get_event_loop()
        func = functools.partial(_func, self, *args, **kwargs)
        return loop.run_in_executor(self.thread_pool, func=func)

    return wrapped


# https://github.com/boto/boto3/issues/1166#issuecomment-313550785
def get_endpoint(service: str, region: str) -> str:
    from_env = os.getenv(f"{service.upper()}_ENDPOINT")
    if from_env:
        return from_env
    loader = botocore.loaders.create_loader()
    data = loader.load_data("endpoints")
    resolver = botocore.regions.EndpointResolver(data)
    endpoint = resolver.construct_endpoint(service, region)
    return f"{endpoint['protocols'][0]}://{endpoint['hostname']}"


def assume_role(
    session: boto3.session.Session,
    role_arn: str,
    session_name: str,
    duration: int = 3600,
) -> boto3.session.Session:
    """
    Assume a role in another account
    """
    sts = session.client("sts")
    response = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=duration
    )
    credentials = response["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


class Ec2SsmInstance:
    def __init__(
        self,
        session: boto3.session.Session,
        name: str,
        *,
        windows: bool = True,
        env: OptionalT[DictT] = None,
        subnet_id: OptionalT[str] = None,
        message_handler: OptionalT[CallableT[..., None]] = None,
        role_arn: OptionalT[str] = None,
        verbose_messages: bool = False,
    ):
        """
        Create an EC2 instance with SSM access

        session: Boto3 Session
        name: Name of the instance
        windows: Whether this is a Windows or Linux instance
        env: Environment variables to pass to the instance
        subnet_id: Optional subnet ID to launch the instance in
        message_handler: Function to call with log messages
        role_arn: Optional ARN of the role to assume
        verbose_messages: Whether to print verbose messages to the message handler
          (may include sensitive information!)
        """
        if role_arn:
            self.session = assume_role(session, role_arn, self.__class__.__name__)
        else:
            self.session = session

        # endpoint_url can be overridden for Mock testing
        self.ec2: EC2Client = self.session.client(
            "ec2", endpoint_url=os.getenv("EC2_ENDPOINT")
        )
        self.ssm = self.session.client("ssm", endpoint_url=os.getenv("SSM_ENDPOINT"))

        self.name = name
        self.id = None
        self.ssm_proc: OptionalT[asyncio.subprocess.Process] = None
        self.ssm_communicate: OptionalT[AwaitableT[asyncio.Task[AnyT]]] = None
        self.socat_proc: OptionalT[asyncio.subprocess.Process] = None
        self.socat_communicate: OptionalT[AwaitableT[asyncio.Task[AnyT]]] = None
        self.ssm_session_id: OptionalT[str] = None
        self.windows = windows
        self.env = env if env else os.environ.copy()
        self.subnet_id = subnet_id
        self.message_handler = message_handler
        self.verbose = verbose_messages

        self.thread_pool = ThreadPoolExecutor(max_workers=2)

    def _log(self, *args):
        if self.message_handler:
            self.message_handler(*args)
        else:
            print(*args)

    @run_in_executor
    def get_instance(self, states: OptionalT[ListT[str]] = None) -> OptionalT[JsonT]:
        return self._get_instance(states)

    # This is called by other methods in this class so it's not async to
    # avoid a method using multiple threads
    def _get_instance(self, states: OptionalT[ListT[str]] = None) -> OptionalT[JsonT]:
        if not states:
            # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html
            # Ignore shutting-down and terminated
            states = ["pending", "running", "stopping", "stopped"]
        kwargs = {}
        if self.id:
            kwargs["InstanceIds"] = [self.id]
        else:
            # https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html#options
            kwargs["Filters"] = [
                {"Name": "instance-state-name", "Values": states},
                {"Name": "tag-key", "Values": ["Name"]},
                {"Name": "tag-value", "Values": [self.name]},
            ]
        reservations = self.ec2.describe_instances(**kwargs)
        instances = [i for r in reservations["Reservations"] for i in r["Instances"]]

        if len(instances) > 1:
            raise RuntimeError(
                f"Expected 0 or 1 instances, found {len(instances)}: {instances}"
            )
        if instances:
            self.id = instances[0]["InstanceId"]
            return instances[0]

        return None

    # This is used by other methods so don't run in executor
    def _get_vpcid(self) -> str:
        """
        Get the VPC ID
        """
        if self.subnet_id:
            subnets = self.ec2.describe_subnets(SubnetIds=[self.subnet_id])["Subnets"]
            if len(subnets) != 1:
                raise RuntimeError(
                    f"Expected 1 subnet with ID {self.subnet_id}, found {len(subnets)}"
                )
            return subnets[0]["VpcId"]
        vpc = self.ec2.describe_vpcs(
            Filters=[
                {"Name": "is-default", "Values": ["true"]},
            ]
        )["Vpcs"]
        if len(vpc) != 1:
            raise RuntimeError(f"Expected 1 default VPC, found {len(vpc)}")
        vpc_id = vpc[0]["VpcId"]
        assert vpc_id
        return vpc_id

    # This is used by other methods so don't run in executor
    def _get_security_group(self, name: str, vpc_id: str) -> OptionalT[JsonT]:
        filters = [
            {
                "Name": "group-name",
                "Values": [name],
            },
            {
                "Name": "vpc-id",
                "Values": [vpc_id],
            },
        ]
        sgs = self.ec2.describe_security_groups(Filters=filters)["SecurityGroups"]
        if len(sgs) > 1:
            raise RuntimeError(f"Found more than one security group name:{name}")
        if sgs:
            return sgs[0]
        return None

    # This is used by other methods so don't run in executor
    def _create_security_group(
        self,
        vpc_id: str,
        ingress_rules: ListT[TupleT[str, int, int]],
        egress_rules: ListT[TupleT[str, int, int]],
    ) -> JsonT:
        """
        Create a security group for the instance.
        If it already exists, delete and recreate all rules.

        ingress_rules: List of (CIDR, port-start, port-end) tuples for ingress rules
        egress_rules: List of (CIDR, port-start, port-end) tuples for egress rules
        """
        sgname = f"ec2-{self.name}"
        sg = self._get_security_group(sgname, vpc_id)
        if not sg:
            self._log(f"Creating security group {sgname}")
            sg = self.ec2.create_security_group(
                Description=f"EC2 {self.name}",
                GroupName=sgname,
                VpcId=vpc_id,
            )
        assert sg
        sgid = sg["GroupId"]

        self._log(f"Deleting existing security group rules {sgname}")
        rules = self.ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [sgid]}]
        )
        for rule in rules["SecurityGroupRules"]:
            if rule["IsEgress"]:
                self.ec2.revoke_security_group_egress(
                    SecurityGroupRuleIds=[rule["SecurityGroupRuleId"]],
                    GroupId=sgid,
                )
            else:
                self.ec2.revoke_security_group_ingress(
                    SecurityGroupRuleIds=[rule["SecurityGroupRuleId"]],
                    GroupId=sgid,
                )

        self._log(f"Creating security group rules {sgname}")
        for cidr, portfrom, portto in ingress_rules:
            self.ec2.authorize_security_group_ingress(
                GroupId=sgid,
                IpPermissions=[
                    {
                        "FromPort": portfrom,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": cidr,
                            },
                        ],
                        "ToPort": portto,
                    },
                ],
            )
        for cidr, portfrom, portto in egress_rules:
            self.ec2.authorize_security_group_egress(
                GroupId=sgid,
                IpPermissions=[
                    {
                        "FromPort": portfrom,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": cidr,
                            },
                        ],
                        "ToPort": portto,
                    },
                ],
            )
        return sg

    def _delete_security_group(self, vpc_id: str):
        """
        Delete the instance's security group
        """
        sgname = f"ec2-{self.name}"
        sg = self._get_security_group(sgname, vpc_id)
        if sg:
            self._log(f"Deleting security group {sgname}")
            sg = self.ec2.delete_security_group(GroupId=sg["GroupId"])

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.run_instances
    @run_in_executor
    def create(
        self,
        *,
        ami_id: str,
        instance_type: str,
        instance_profile_name: str,
        key_name: OptionalT[str] = None,
        userdata: OptionalT[str] = None,
        volume_size: int = 0,
        shutdown_terminate: bool = False,
        ingress_rules: OptionalT[ListT[TupleT[str, int, int]]] = None,
        egress_rules: OptionalT[ListT[TupleT[str, int, int]]] = None,
        wait: bool = True,
    ) -> JsonT:
        """
        Create an EC2 instance

        ingress_rules: List of (CIDR, port-start, port-end) tuples for ingress rules
        egress_rules: List of (CIDR, port-start, port-end) tuples for egress rules
        """
        self._get_instance()
        if self.id:
            raise RuntimeError(f"Instance already created: {self.name} {self.id}")

        vpc_id = self._get_vpcid()

        sg = self._create_security_group(
            vpc_id, ingress_rules or [], egress_rules or []
        )

        kwargs = dict(
            IamInstanceProfile={"Name": instance_profile_name},
            ImageId=ami_id,
            InstanceType=instance_type,
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[sg["GroupId"]],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": self.name}],
                }
            ],
        )
        if key_name:
            kwargs["KeyName"] = key_name
        if userdata:
            kwargs["UserData"] = userdata
        if volume_size:
            kwargs["BlockDeviceMappings"] = [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": volume_size,
                        "VolumeType": "gp3",
                        "Encrypted": True,
                    },
                }
            ]
            kwargs["HibernationOptions"] = {"Configured": True}
        if shutdown_terminate:
            kwargs["InstanceInitiatedShutdownBehavior"] = "terminate"
        if self.subnet_id:
            kwargs["SubnetId"] = self.subnet_id

        if self.verbose:
            self._log(f"Creating instance {self.name}: {kwargs}")
        else:
            self._log(f"Creating instance {self.name}")
        r = self.ec2.run_instances(**kwargs)
        instance = r["Instances"][0]
        self.id = instance["InstanceId"]
        if wait:
            self._wait_instance_state("running")
        return instance

    @run_in_executor
    def start(self, wait: bool = True) -> JsonT:
        """
        Start instance

        wait: Wait for instance to start
        """
        instance = self._get_instance()
        if not instance:
            raise RuntimeError(f"Instance not found: {self.name}")
        if instance["State"]["Name"] == "stopping":
            # Can't start an instance that is stopping
            self._log(f"Instance {self.name} is stopping, waiting...")
            self._wait_instance_state("stopped")
        # It's fine to call start on a pending/running instance
        self._log(f"Starting instance {self.name}")
        r = self.ec2.start_instances(InstanceIds=[self.id])
        if wait:
            self._wait_instance_state("running")
        return r["StartingInstances"]

    @run_in_executor
    def stop(self, wait: bool = True) -> JsonT:
        """
        Stop instance

        wait: Wait for instance to stop

        If instance is already stopped or stopping returns None
        """
        instance = self._get_instance()
        if not instance:
            raise RuntimeError(f"Instance not found: {self.name}")
        # It's fine to call stop on a stopping/stopped instance
        self._log(f"Hibernating instance {self.name}")
        try:
            r = self.ec2.stop_instances(InstanceIds=[self.id], Hibernate=True)
        except self.ec2.exceptions.ClientError as exc:
            self._log(exc)
            if exc.response["Error"]["Code"] == "UnsupportedHibernationConfiguration":
                self._log(f"Hibernation failed, stopping instance {self.name}")
                r = self.ec2.stop_instances(InstanceIds=[self.id])

        if wait:
            self._wait_instance_state("stopped")
        return r["StoppingInstances"]

    @run_in_executor
    def delete(self, wait: bool = True) -> JsonT:
        """
        Delete (terminate) instance

        wait: Wait for instance to terminate
        """
        r = None
        instance = self._get_instance()
        if instance:
            self._log(f"Deleting instance {self.name}")
            r = self.ec2.terminate_instances(InstanceIds=[self.id])[
                "TerminatingInstances"
            ]
            if wait:
                self._wait_instance_state("terminated")
        self.id = None
        vpc_id = self._get_vpcid()
        self._delete_security_group(vpc_id)
        if not instance:
            raise RuntimeError(f"Instance not found: {self.name}")
        assert r
        return r

    # This is used by other methods so don't run in executor
    def _wait(
        self,
        f: CallableT[..., AnyT],
        *,
        initial_delay: OptionalT[int] = None,
        poll_interval: int = 10,
        max_wait: int = 300,
        timeout_message: OptionalT[str] = None,
    ) -> AnyT:
        t_start = time.time()
        elapsed = 0.0
        if not timeout_message:
            timeout_message = f"Timeout error after {max_wait} s"
        delay = initial_delay if initial_delay is not None else poll_interval

        while True:
            time.sleep(delay)
            delay = poll_interval
            elapsed = time.time() - t_start
            r = f(elapsed=elapsed)
            if r:
                return r
            if elapsed > max_wait:
                raise RuntimeError(timeout_message)
        # Silence mypy
        return None

    @run_in_executor
    def wait_instance(
        self, state: str, poll_interval: int = 10, max_wait: int = 300
    ) -> JsonT:
        """
        Wait for the instance to be in a desired state (running, stopped, terminated)

        state: Desired state
        poll_interval: Check state every `poll_interval` seconds
        max_wait: If instance isn't in desired state after `max_wait` seconds throws an
        exception
        """
        return self._wait_instance_state(state, poll_interval, max_wait)

    # This is used by other methods so don't run in executor
    def _wait_instance_state(
        self, state: str, poll_interval: int = 10, max_wait: int = 300
    ) -> JsonT:
        """
        Wait for the instance to be in a desired state

        state: Wait for instance to be in this state
        poll_interval: Check state every `poll_interval` seconds
        max_wait: If instance isn't `stopped` after `max_wait` seconds throws an
        exception
        """
        if not self.id:
            raise RuntimeError(f"Instance not found: {self.name}")

        valid_starting_states = {
            "running": ["pending", "rebooting"],
            "stopped": ["stopping", "stopped"],
            "terminated": ["shutting-down", "terminated"],
        }
        valid_states = valid_starting_states[state]
        if state not in valid_starting_states:
            raise ValueError(f"Invalid state to wait for: {state}")

        def check_instance(elapsed: int):
            instance = self._get_instance()
            if not instance:
                self._log(f"[{elapsed:.3f}] Instance {self.id} not found")
                return
            current_state = instance["State"]["Name"]
            self._log(f"[{elapsed:.3f}] Instance {self.id} {current_state}")
            if current_state == state:
                return instance
            if current_state not in valid_states:
                raise RuntimeError(
                    (
                        f"Instance {self.id} is not in any of states "
                        f"{valid_states}: {current_state}"
                    )
                )

        return self._wait(
            check_instance,
            # There may be a delay between e.g starting and instance, and the instances
            # state being "starting", so don't check straight away
            initial_delay=poll_interval,
            poll_interval=poll_interval,
            max_wait=max_wait,
            timeout_message=(
                f"Instance {self.id} not in state {state} after {max_wait} s",
            ),
        )

    @run_in_executor
    def wait_ssm_online(self, poll_interval: int = 10, max_wait: int = 600) -> JsonT:
        """
        Wait for the instance to be ready to receive SSM commands

        poll_interval: Check readiness every `poll_interval` seconds
        max_wait: If instance isn't read after `max_wait` seconds throws an exception
        """
        if not self.id:
            raise RuntimeError(f"Instance not found: {self.name}")

        def check_ssm(elapsed):
            instances = self.ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [self.id]}]
            )["InstanceInformationList"]
            if instances:
                instance = instances[0]
                self._log(f"[{elapsed:.3f}] {instance['PingStatus']}")
                if instance["PingStatus"] == "Online":
                    return instance
            else:
                self._log(f"[{elapsed:.3f}] SSM Instance {self.id} not found")

        return self._wait(
            check_ssm,
            initial_delay=0,
            poll_interval=poll_interval,
            max_wait=max_wait,
            timeout_message=f"SSM Instance {self.id} not online after {max_wait} s",
        )

    @run_in_executor
    def ssm_commands(
        self, commands: ListT[str], poll_interval: int = 1, max_wait: int = 300
    ) -> JsonT:
        """
        Run a Powershell (Windows) or shell (Linux) commands using SSM,
        wait for command to return

        poll_interval: Check for completion every `poll_interval` seconds
        max_wait: If command hasn't returned `max_wait` seconds throws an exception

        returns: Dict containing the output of the SSM command
        """
        if not self.id:
            raise RuntimeError(f"Instance not found: {self.name}")

        if self.windows:
            document_name = "AWS-RunPowerShellScript"
        else:
            document_name = "AWS-RunShellScript"
        # https://stackoverflow.com/a/48094004
        r = self.ssm.send_command(
            InstanceIds=[self.id],
            DocumentName=document_name,
            Parameters={"commands": commands},
        )

        def check_command(elapsed):
            output = self.ssm.get_command_invocation(
                CommandId=r["Command"]["CommandId"], InstanceId=self.id
            )
            if output["Status"] == "InProgress":
                self._log(f"{elapsed:.3f} {output['Status']}")
            else:
                return output

        return self._wait(
            check_command,
            poll_interval=poll_interval,
            max_wait=max_wait,
            timeout_message=f"SSM Command hasn't completed after {max_wait} s",
        )

    @run_in_executor
    def ssm_start_session(
        self, local_port: int, remote_port: int
    ) -> TupleT[JsonT, JsonT]:
        """
        Starts the SSM component of a port-forwarding session

        local_port: Local port
        remote_port: Remote port

        returns: Tuple: The SSM session, and parameters that can be passed to the
        session-manager-plugin
        """
        if not self.id:
            raise RuntimeError(f"Instance not found: {self.name}")

        if self.ssm_session_id:
            raise RuntimeError(f"SSM session already started: {self.ssm_session_id}")
        parameters = {
            "Target": self.id,
            "DocumentName": "AWS-StartPortForwardingSession",
            "Parameters": {
                "localPortNumber": [f"{local_port}"],
                "portNumber": [f"{remote_port}"],
            },
        }
        r = self.ssm.start_session(**parameters)
        self.ssm_session_id = r["SessionId"]
        return r, parameters

    # aws ssm start-session .... launches session-manager-plugin in a subprocess
    # but killing aws ssm doesn't kill the child process :-(
    # Instead call session-manager-plugin directly.
    # Parameters are taken from the AWS CLI source code:
    # https://github.com/aws/aws-cli/blob/45b0063b2d0b245b17a57fd9eebd9fcc87c4426a/awscli/customizations/sessionmanager.py#L83-L89
    async def ssm_port_start(
        self, local_port: int, remote_port: int, additional_addr: OptionalT[str] = None
    ) -> TupleT[
        asyncio.subprocess.Process,
        AwaitableT[asyncio.Task[AnyT]],
        OptionalT[asyncio.subprocess.Process],
        OptionalT[AwaitableT[asyncio.Task[AnyT]]],
    ]:
        """
        Starts a SSM port-forwarding session including a local session-manager-plugin

        local_port: Local port
        remote_port: Remote port

        additional_addr: Listen on an additional local address
          session-manager-plugin only listens on localhost, use socat to forward

        returns: Tuple: The SSM session, and parameters that can be passed to the
        session-manager-plugin
        """
        if not self.id:
            raise RuntimeError(f"Instance not found: {self.name}")

        response, parameters = await self.ssm_start_session(local_port, remote_port)

        cmd = "session-manager-plugin"
        args = [
            json.dumps(response),
            self.session.region_name,
            "StartSession",
            self.session.profile_name,
            json.dumps(parameters),
            get_endpoint("ssm", self.session.region_name),
        ]
        self.ssm_proc, self.ssm_communicate = await run_background_process(
            cmd, args, self.env
        )

        if additional_addr:
            self.socat_proc, self.socat_communicate = await run_background_process(
                "socat",
                [
                    f"TCP-LISTEN:{local_port},bind={additional_addr},fork",
                    f"TCP:127.0.0.1:{local_port}",
                ],
            )
        return (
            self.ssm_proc,
            self.ssm_communicate,
            self.socat_proc,
            self.socat_communicate,
        )

    @run_in_executor
    def ssm_stop_session(self) -> None:
        if self.ssm_session_id:
            self._log(f"Stopping session {self.ssm_session_id}")
            self.ssm.terminate_session(SessionId=self.ssm_session_id)
            self.ssm_session_id = None

    async def ssm_port_stop(self) -> None:
        if self.ssm_proc:
            self.ssm_proc.terminate()
            await self.ssm_proc.wait()
            if self.ssm_communicate:
                stdout, stderr = await self.ssm_communicate
                self._log(f"[Exit code] {self.ssm_proc.returncode}")
            else:
                self._log("ERROR: ssm_communicate is missing")
            self.ssm_proc = None
            if stdout:
                self._log(f"[stdout]\n{stdout.decode()}")
            if stderr:
                self._log(f"[stderr]\n{stderr.decode()}")
            self.ssm_communicate = None

        if self.socat_proc:
            self.socat_proc.terminate()
            await self.socat_proc.wait()
            if self.socat_communicate:
                stdout, stderr = await self.socat_communicate
                self._log(f"[Exit code] {self.socat_proc.returncode}")
            else:
                self._log("ERROR: socat_communicate is missing")
            self.socat_proc = None
            if stdout:
                self._log(f"[stdout]\n{stdout.decode()}")
            if stderr:
                self._log(f"[stderr]\n{stderr.decode()}")
            self.socat_communicate = None

        await self.ssm_stop_session()

    @run_in_executor
    def find_ami(
        self,
        *,
        owner: OptionalT[str] = None,
        name: OptionalT[str] = None,
        **kwargs: DictT[str, str],
    ) -> OptionalT[DictT[str, AnyT]]:
        """
        Finds an available AMI

        owner: AWS account ID or an alias such as `amazon`
        name: Name of the AMI, can contain a wildcard
        kwargs: Additional search filters, e.g. {"architecture": "x86_64"}
        """
        filters_dict = {
            "state": "available",
        }
        if name is not None:
            filters_dict["name"] = name
        for k, v in kwargs.items():
            if not isinstance(v, str):
                raise TypeError(f"Invalid value type: {v}")
            filters_dict[k] = v

        filters: ListT[DictT[str, UnionT[str, ListT[str]]]] = []
        for kf, vf in filters_dict.items():
            filters.append({"Name": kf, "Values": [vf]})

        if owner:
            owners = [owner]
        else:
            owners = []

        images = self.ec2.describe_images(Owners=owners, Filters=filters)["Images"]
        if images:
            return sorted(images, key=lambda i: i["CreationDate"], reverse=True)[0]
        return None
