"""
JupyterHub spawner that launches EC2 instances and for running a virtual
desktop as a singleuser server, accessed via Kubernetes
"""
import asyncio
import logging
import string
from random import choices
from typing import Any as AnyT
from typing import AsyncGenerator as AsyncGeneratorT
from typing import Dict as DictT
from typing import Optional as OptionalT
from typing import Tuple as TupleT
from typing import Union as UnionT

import boto3
from aiostream import stream
from kubespawner import KubeSpawner
from traitlets import Bool, Dict, Instance, Int, Unicode

try:
    from .awsec2 import Ec2SsmInstance
except ImportError:
    from awsec2 import Ec2SsmInstance  # type: ignore

JsonT = DictT[str, AnyT]

logger = logging.getLogger(__name__)


class Ec2Exception(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    def __str__(self):
        return f"Ec2Exception: {self.args[0]}"


def _clean_dict(d):
    r = {}
    for k, v in d.items():
        if k.lower() in ["password", "secret", "token"]:
            r[k] = "*****"
        elif isinstance(v, dict):
            r[k] = _clean_dict(v)
        elif isinstance(v, list):
            r[k] = [_clean_dict(i) for i in v]
        else:
            r[k] = str(v)
    return r


class Ec2DesktopSpawner(KubeSpawner):
    # Configuration properties

    ami_search = Dict(
        {
            "owner": "amazon",
            "name": "Windows_Server-2022-English-Full-Base-*",
            "architecture": "x86_64",
        },
        config=True,
        allow_none=False,
        help=(
            "EC2 AMI ID search parmeters, must include `owner` and `name`. "
            "Other parameters are passed as additional filters. "
            "See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images. "
            "Ignored if `ami_id` is set."
        ),
    )

    ami_id = Unicode(
        config=True,
        allow_none=True,
        help="EC2 AMI ID, use `ami_id_search` to automatically find an AMI",
    )

    instance_type = Unicode("t3a.micro", config=True, help="EC2 instance type")

    instance_profile_name = Unicode(
        "AmazonSSMRoleForInstancesQuickSetup",
        config=True,
        allow_none=False,
        help="IAM instance profile name, must allow SSM",
    )

    subnet_id = Unicode(
        None,
        config=True,
        allow_none=True,
        help="Subnet ID to launch instance in",
    )

    userdata = Unicode("", config=True, help="UserData block")

    volume_size = Int(30, config=True, help="Volume size in GB")

    shutdown_terminate = Bool(
        config=True,
        default=False,
        help="Delete instance if shutdown by user inside the operating system",
    )

    cidr_in = Unicode("0.0.0.0/0", config=True, help="CIDR to allow RDP from")
    cidr_out = Unicode(
        "0.0.0.0/0", config=True, help="CIDR to allow all outbound traffic to"
    )

    windows = Bool(
        config=True,
        default=False,
        help="Set to True if this is a Windows instance, should be autodetected from AMI metadata",
    )

    # Non-config properties

    ec2_events = Instance(
        asyncio.Queue,
        args=(),
        help="""
        Queue for events that are shown to the user
        https://asyncio.readthedocs.io/en/latest/producer_consumer.html
        """,
    )

    session = Instance(boto3.session.Session, args=(), help="AWS client session")

    ec2instance = Instance(
        Ec2SsmInstance,
        allow_none=True,
        help="EC2 instance wrapper",
    )

    ec2_connection_info = Dict({}, help="Connection info for EC2 instance")

    kubespawner_started = Instance(
        asyncio.Event, args=(), help="Whether kubespawner.start() has been called"
    )

    def _put_ec2_event(self, event: OptionalT[DictT]) -> None:
        if event and "message" in event:
            self.log.info(event["message"])
        self.ec2_events.put_nowait(event)

    def get_env(self):
        env = super().get_env()
        for k, v in self.ec2_connection_info.items():
            env[k.upper()] = v
        return env

    def load_state(self, state: dict) -> None:
        super().load_state(state)
        self.ec2_connection_info = state.get("ec2_connection_info", {})
        ami_id = state.get("ami_id")
        if ami_id and self.ami_id and ami_id != self.ami_id:
            self.log.warning(
                f"Configured ami_id {self.ami_id} does not match loaded state {ami_id}"
            )
            self.ami_id = ami_id
        self.windows = state.get("windows", self.windows)

    def get_state(self) -> JsonT:
        state = super().get_state()
        state["ec2_connection_info"] = self.ec2_connection_info
        state["ami_id"] = self.ami_id
        state["windows"] = self.windows
        return state

    async def _get_instance_ip(self) -> str:
        instance = await self.ec2instance.get_instance()
        return instance["NetworkInterfaces"][0]["PrivateIpAddress"]

    async def _update_ec2_connection_windows(self) -> None:
        username, password = self._get_username_password()

        # Note if this is called too early the EC2Launch script may overwrite the
        # password. Set the password in userdata instead, and only use this as a backup
        win_command = f"net user {username} {password}"
        self._put_ec2_event({"message": "Setting windows password"})
        await self.ec2instance.ssm_commands([win_command])

        self.ec2_connection_info = {
            "username": username,
            "password": password,
            "hostname": await self._get_instance_ip(),
            "protocol": "rdp",
        }

    async def _get_ami(self):
        if self.ami_id:
            ami_kwargs = {"image-id": self.ami_id}
        else:
            ami_kwargs = self.ami_search
        self._put_ec2_event({"message": f"Searching for AMI {ami_kwargs}"})
        ami = await self.ec2instance.find_ami(**ami_kwargs)
        if not ami:
            raise RuntimeError(f"No matching AMI found {ami_kwargs}")
        self.ami_id = ami["ImageId"]
        if ami["Platform"] == "windows":
            self.windows = True
        return ami

    def _get_username_password(self):
        username = self.ec2_connection_info.get("username")
        if not username:
            if self.windows:
                username = "Administrator"
                self.ec2_connection_info["username"] = username
            else:
                raise RuntimeError("Unknown EC2 username")
        password = self.ec2_connection_info.get("password")
        if not password:
            password = "".join(choices(string.ascii_letters + string.digits, k=32))
            self.ec2_connection_info["password"] = password
        return username, password

    def _get_userdata(self):
        if self.windows:
            username, password = self._get_username_password()
            userdata = "\n".join(
                [
                    "<powershell>",
                    f"net user {username} {password}",
                    self.userdata,
                    "</powershell>",
                ]
            )
        else:
            userdata = self.userdata
        return userdata

    async def start(self) -> TupleT[str, int]:
        instance_name = self.pod_name
        self._put_ec2_event({"message": f"Starting {instance_name}"})

        self.ec2instance = Ec2SsmInstance(
            self.session,
            instance_name,
            subnet_id=self.subnet_id,
            message_handler=lambda m: self._put_ec2_event(
                {"message": f"Ec2SsmInstance: {m}"}
            ),
        )
        instance = await self.ec2instance.get_instance()

        if instance:
            self.log.info(f"Instance: {self.ec2instance.id}")
        else:
            self.log.info(f"No instances matching Name={instance_name}")

        if not instance:
            self.ec2_connection_info = {}
            self._put_ec2_event({"message": f"Creating instance [{instance_name}]"})

            await self._get_ami()

            instance = await self.ec2instance.create(
                ami_id=self.ami_id,
                instance_type=self.instance_type,
                instance_profile_name=self.instance_profile_name,
                userdata=self._get_userdata(),
                volume_size=self.volume_size,
                shutdown_terminate=self.shutdown_terminate,
                ingress_rules=[(self.cidr_in, 3389, 3389)],
                egress_rules=[(self.cidr_out, 0, 65535)],
            )
        else:
            self._put_ec2_event(
                {
                    "message": f"Instance already exists [{instance_name}]"
                    f"({instance['State']['Name']})"
                }
            )

        await self.ec2instance.start()
        self.log.debug(f"Instance: {self.ec2instance.id}")

        self._put_ec2_event({"message": "Waiting for instance connection"})
        await self.ec2instance.wait_ssm_online()

        # Always update the connection info, including resetting the password
        if self.windows:
            await self._update_ec2_connection_windows()
        else:
            raise NotImplementedError("Only Windows is implemented")

        self._put_ec2_event(
            {"message": f"EC2 instance ready: {_clean_dict(self.ec2_connection_info)}"}
        )

        async def _set_kube_spawner_started():
            self.kubespawner_started.set()

        return (await asyncio.gather(super().start(), _set_kube_spawner_started()))[0]

    async def stop(self, now=False) -> None:
        # TODO or not bother?
        #   now=False (default), shutdown the server gracefully
        #   now=True, terminate the server immediately.
        try:
            await self.ec2instance.stop()
        except Exception as e:
            self.log.error(f"ec2instance.stop failed: {e}")
        await super().stop(now)

    async def poll(self) -> UnionT[None, int]:
        # None: single-user process is running.
        # Integer: not running, return exit status (0 if unknown)
        # Spawner not initialized: behave as not running (0).
        # Spawner not finished starting: behave as running (None)
        # May be called before start when state is loaded on Hub launch,
        #   if spawner not initialized via load_state or start: unknown (0)
        # If called while start is in progress (yielded): running (None)

        if self.ec2instance:
            instance = await self.ec2instance.get_instance()
            if not instance:
                self.ec2_connection_info = {}
            if (
                instance
                and instance["State"]["Name"] in ("pending", "running")
                and self.ec2_connection_info
            ):
                return await super().poll()

        if await super().poll() != 0:
            self.log.warning("Instance not running but pods found, stopping")
            # TODO: Race condition, what if instance is starting, and we stop these
            # pods at the same time as super().start() is called?
            await super().stop(True)
        return 0

    async def _ec2_progress(self) -> AsyncGeneratorT[int, None]:
        """
        https://github.com/jupyterhub/jupyterhub/blob/1.1.0/jupyterhub/spawner.py#L1009-L1032
        """
        while True:
            event = await self.ec2_events.get()
            if event is None:
                break
            yield event

    async def _kubespawner_progress(self) -> AsyncGeneratorT[int, None]:
        # Only fetch KubeSpawner events after it has started, as there may be some old
        # k8s events
        # self.log.error(f"kubespawner_started: {self.kubespawner_started.is_set()}")
        # assert not self.kubespawner_started.is_set()
        await self.kubespawner_started.wait()
        # self.log.error(f"kubespawner_started: {self.kubespawner_started.is_set()}")
        async for event in super().progress():
            yield event

    async def progress(self) -> AsyncGeneratorT[int, None]:
        async with stream.merge(
            self._ec2_progress(), self._kubespawner_progress()
        ).stream() as streamer:
            async for event in streamer:
                yield event
