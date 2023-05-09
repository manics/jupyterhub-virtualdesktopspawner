# JupyterHub Virtual Desktop Spawner

[![Build](https://github.com/manics/jupyterhub-virtualdesktopspawner/actions/workflows/workflow.yml/badge.svg)](https://github.com/manics/jupyterhub-virtualdesktopspawner/actions/workflows/workflow.yml)

**⚠️⚠️⚠️⚠️⚠️ Under development ⚠️⚠️⚠️⚠️⚠️**

Run Linux or Windows desktops with JupyterHub on public cloud and Kubernetes.

Linux desktops can be run in Linux containers on Kubernetes.

Windows desktops can only be run in a virtual machine- Microsoft does not allow desktops to be run in a Windows container.
Support for AWS EC2 is provided.

Apache Guacamole, running on Kubernetes, provides browser access to the desktops.

Example of connecting to a shutdown Windows desktop:

[windows-existing-launch.webm](https://user-images.githubusercontent.com/1644105/236957323-5efb2a6c-0e4e-434c-a1e9-bd9a732f0589.webm)

## Setup: Linux desktops (containers)

p
Use [z2jh-linuxdesktops.yaml](./configs/z2jh-linuxdesktops.yaml) as the Z2JH configuration.

## Setup: Windows desktops (virtual machines)

Currently only AWS EC2 is supported.

Create an [IRSA role](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) with the policy in [aws-ec2ssm-iam-policy.json](./aws-iam/aws-ec2ssm-iam-policy.json) so that JupyterHub can access EC2 and SSM.
Ensure the role can be assumed by the `hub` service account in whichever Kubernetes namespace you're using.
Alternatively create an IAM role and credentials, and pass them to the hub pod as environment variables.

Install JupyterHub following [Zero to JupyterHub with Kubernetes](https://z2jh.jupyter.org/en/stable/).
Use [z2jh-windowsdesktops.yaml](./configs/z2jh-windowsdesktops.yaml) as the Z2JH configuration. Change:

- `hub.config.Ec2DesktopSpawner.subnet_id`: The VPC subnet ID that the instance should be created in
- `hub.config.Ec2DesktopSpawner.instance_profile_name`: Instance profile role name, must allow SSM access

## More screenshots

Example of creating a new Windows desktop:

[windows-create-launch.webm](https://user-images.githubusercontent.com/1644105/236957513-2fa86617-6aeb-4530-b526-0b559ad13985.webm)
