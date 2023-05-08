# JupyterHub Virtual Desktop Spawner

**⚠️⚠️⚠️⚠️⚠️ Under development ⚠️⚠️⚠️⚠️⚠️**

Run Linux or Windows desktops with JupyterHub on public cloud and Kubernetes.

Linux desktops can be run in Linux containers on Kubernetes.

Windows desktops can only be run in a virtual machines- Microsoft does not allow desktops to be run in a Windows container.
Support for AWS EC2 is provided.

Apache Guacamole provide browser access to the desktops.

## Setup: Linux desktops (containers)

Install JupyterHub following [Zero to JupyterHub with Kubernetes](https://z2jh.jupyter.org/en/stable/).
Use [z2jh-linuxdesktops.yaml](./configs/z2jh-linuxdesktops.yaml) as the Z2JH configuration.

## Setup: Windows desktops (virtual machines)

Currently only AWS EC2 is supported.

Create an IRSA role with the policy in [awsec2-iam-policy.json](./aws-iam/awsec2-iam-policy.json) so that JupyterHub can access EC2 and SSM. Ensure the role can be assumed by the `hub` service account in whichever Kubernetes namespace you're using.

Use [z2jh-linuxdesktops.yaml](./configs/z2jh-windowsdesktops.yaml) as the Z2JH configuration. Change:

- `c.Ec2DesktopSpawner.subnet_id`: THe VPC subnet ID that the instance should be created in
- `c.Ec2DesktopSpawner.ami_id`: EC2 AMI ID
- `c.Ec2DesktopSpawner.instance_type` = EC2 instance type("t3a.micro", config=True, help="EC2 instance type")
- `c.Ec2DesktopSpawner.instance_profile_name`: Instance profile role nam, must allow SSM access
