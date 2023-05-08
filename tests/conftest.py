""" pytest config  tests """
import os
from uuid import uuid4

import boto3
import pytest


@pytest.fixture
def aws_session(monkeypatch):
    """
    Create a localstack mock session
    """
    monkeypatch.setenv("EC2_ENDPOINT", "http://localhost:4566")
    monkeypatch.setenv("SSM_ENDPOINT", "http://localhost:4566")
    session = boto3.session.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name="eu-west-2"
    )
    yield session


@pytest.fixture
def instance_name():
    """
    Create a localstack mock session
    """
    yield str(uuid4())


@pytest.fixture
def create_args():
    """
    Mock arguments for ec2.run_instances
    """
    return {
        "ami_id": "ami-id",
        "instance_type": "instance.type",
        # "instance_profile_name": "instance-profile",
        "instance_profile_name": "",
        "ingress_rules": [("10.1.2.3/8", 11111, 22222)],
        "egress_rules": [("192.168.1.2/24", 33333, 44444)],
    }


@pytest.fixture
def default_vpc(aws_session):
    """
    Return the default VPC, and None for the subnet
    """
    ec2 = aws_session.client("ec2", endpoint_url=os.getenv("EC2_ENDPOINT"))
    vpcs = ec2.describe_vpcs(
        Filters=[
            {"Name": "is-default", "Values": ["true"]},
        ]
    )["Vpcs"]
    assert len(vpcs) == 1
    return vpcs[0]["VpcId"], None


@pytest.fixture
def aws_vpc(aws_session):
    """
    Create a new VPC and subnet
    """
    ec2 = aws_session.client("ec2", endpoint_url=os.getenv("EC2_ENDPOINT"))
    vpc_id = ec2.create_vpc(CidrBlock="192.168.250.0/24")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="192.168.250.0/28")["Subnet"][
        "SubnetId"
    ]
    yield vpc_id, subnet_id

    ec2.delete_subnet(SubnetId=subnet_id)
    ec2.delete_vpc(VpcId=vpc_id)
