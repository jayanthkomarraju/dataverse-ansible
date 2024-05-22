#!/bin/bash -e

# repo and branch defaults
REPO_URL_DEFAULT="https://github.com/IQSS/dataverse.git"
BRANCH_DEFAULT="develop"
PEM_DEFAULT="${HOME}"
VERBOSE_ARG=""


# rocky linux 9.3 official, us-east-1
#AWS_AMI_DEFAULT='ami-06b7b440778b965d8'
# let's stick with rocky 8.9 until ITs pass
AWS_AMI_DEFAULT='ami-0408f4c4a072e3fb9'

usage() {
  cat << EOF
Usage: $0 [options]
Options:
  -b <branch>            Branch to deploy (default: develop)
  -r <repo>              GitHub repository URL (default: https://github.com/IQSS/dataverse)
  -p <pem_path>          Path to PEM file (default: ${HOME})
  -g <group_vars>        Ansible group variables file URL
  -a <dataverse-ansible> Dataverse Ansible branch
  -i <aws_image>         AWS AMI ID (default: $AWS_AMI_DEFAULT)
  -u <aws_user>          AWS user (default: rocky)
  -s <aws_size>          AWS instance size (default: t3a.large)
  -t <aws_tag>           AWS tag
  -f <aws_security>      AWS security group (default: dataverse-sg)
  -e <aws_profile>       AWS profile
  -l <local_log_path>    Local log path
  -d                     Destroy AWS instance after use
  -v                     Increase Ansible verbosity
EOF
  exit 1
}

# Parse options
while getopts ":a:r:b:g:p:i:u:s:t:f:e:l:dv" o; do
  case "${o}" in
    a) DA_BRANCH=${OPTARG} ;;
    r) REPO_URL=${OPTARG} ;;
    b) BRANCH=${OPTARG} ;;
    g) GRPVRS=${OPTARG} ;;
    p) PEM_PATH=${OPTARG} ;;
    i) AWS_IMAGE=${OPTARG} ;;
    u) AWS_USER=${OPTARG} ;;
    s) AWS_SIZE=${OPTARG} ;;
    t) TAG=${OPTARG} ;;
    f) AWS_SG=${OPTARG} ;;
    l) LOCAL_LOG_PATH=${OPTARG} ;;
    e) AWS_PROFILE=${OPTARG} ;;
    d) DESTROY=true ;;
    v) VERBOSE=true ;;
    *) usage ;;
  esac
done

# Set defaults if not provided
REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
BRANCH="${BRANCH:-$BRANCH_DEFAULT}"
PEM_PATH="${PEM_PATH:-$PEM_DEFAULT}"
AWS_IMAGE="${AWS_IMAGE:-$AWS_AMI_DEFAULT}"
AWS_USER="${AWS_USER:-rocky}"
AWS_SIZE="${AWS_SIZE:-t3a.large}"
AWS_SG="${AWS_SG:-dataverse-sg}"
DA_BRANCH="${DA_BRANCH:-develop}"

GVFILE=""
GVARG=""
if [ -n "$GRPVRS" ]; then
  GVFILE=$(basename "$GRPVRS")
  GVARG="-e @$GVFILE"
  echo "using $GRPVRS for extra vars"
  echo "deploying $BRANCH from $GRPVRS"
fi

if [ -n "$REPO_URL" ]; then
  GVARG+=" -e dataverse_repo=$REPO_URL"
  echo "using repo $REPO_URL"
fi

if [ -n "$BRANCH" ]; then
  GVARG+=" -e dataverse_branch=$BRANCH"
  echo "building branch $BRANCH"
fi

if [ -n "$TAG" ]; then
  TAGARG="--tag-specifications ResourceType=instance,Tags=[{Key=name,Value=$TAG}]"
  echo "using tag $TAG"
fi

if [ -n "$AWS_PROFILE" ]; then
  PROFILE="--profile=$AWS_PROFILE"
  echo "using profile $PROFILE"
fi

if [ -n "$VERBOSE" ]; then
  VERBOSE_ARG="-v"
fi

# Check AWS CLI availability
AWS_CLI_VERSION=$(aws --version)
if [[ "$?" -ne 0 ]]; then
  echo 'The "aws" program could not be executed. Is it in your $PATH?'
  exit 1
fi

# Verify branch existence if no group_vars specified
if [ -z "$GRPVRS" ]; then
  if [[ $(git ls-remote --heads $REPO_URL $BRANCH | wc -l) -eq 0 ]]; then
    echo "Branch \"$BRANCH\" does not exist at $REPO_URL"
    usage
    exit 1
  fi
fi

# Create resources on AWS
VPC_ID=$(aws $PROFILE ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)
echo "Created VPC with ID: $VPC_ID"

IGW_ID=$(aws $PROFILE ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)
aws $PROFILE ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
echo "Created and attached internet gateway with ID: $IGW_ID"

SUBNET_ID=$(aws $PROFILE ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --query 'Subnet.SubnetId' --output text)
echo "Created subnet with ID: $SUBNET_ID"

ROUTE_TABLE_ID=$(aws $PROFILE ec2 create-route-table --vpc-id $VPC_ID --query 'RouteTable.RouteTableId' --output text)
aws $PROFILE ec2 create-route --route-table-id $ROUTE_TABLE_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
aws $PROFILE ec2 associate-route-table --subnet-id $SUBNET_ID --route-table-id $ROUTE_TABLE_ID
echo "Created route table with ID: $ROUTE_TABLE_ID and associated it with the subnet"

GROUP_CHECK=$(aws $PROFILE ec2 describe-security-groups --group-name $AWS_SG)
if [[ "$?" -ne 0 ]]; then
  echo "Creating security group \"$AWS_SG\"."
  SG_ID=$(aws $PROFILE ec2 create-security-group --group-name $AWS_SG --description "security group for Dataverse" --vpc-id $VPC_ID --query 'GroupId' --output text)
  aws $PROFILE ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0
  aws $PROFILE ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 80 --cidr 0.0.0.0/0
  aws $PROFILE ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0
  aws $PROFILE ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 8080 --cidr 0.0.0.0/0
else
  SG_ID=$(aws $PROFILE ec2 describe-security-groups --group-names $AWS_SG --query 'SecurityGroups[0].GroupId' --output text)
fi

# PEM file handling
if [ -n "$PEM_PATH" ]; then
  KEY_NAME=$(basename "$PEM_PATH" .pem)
  echo "using key_name: $KEY_NAME"
else
  RANDOM_STRING="$(uuidgen | cut -c-8)"
  KEY_NAME="key-$USER-$RANDOM_STRING"
  echo "using key_name: $KEY_NAME"
  PRIVATE_KEY=$(aws $PROFILE ec2 create-key-pair --key-name "$KEY_NAME" --query 'KeyMaterial' --output text)
  if [[ $PRIVATE_KEY == '-----BEGIN RSA PRIVATE KEY-----'* ]]; then
    PEM_FILE="${HOME}/$KEY_NAME.pem"
    printf -- "$PRIVATE_KEY" >"$PEM_FILE"
    chmod 400 "$PEM_FILE"
    echo "Your newly created private key file is \"$PEM_FILE\". Keep it secret. Keep it safe."
    KEY_NAME="$PEM_FILE"
  else
    echo "Could not create key pair. Exiting."
    exit 1
  fi
fi

echo "Creating EC2 instance"
INSTANCE_ID=$(aws $PROFILE ec2 run-instances --image-id $AWS_IMAGE --security-group-ids $SG_ID --subnet-id $SUBNET_ID $TAGARG --count 1 --instance-type $AWS_SIZE --key-name $KEY_NAME --query 'Instances[0].InstanceId' --block-device-mappings '[ { "DeviceName": "/dev/sda1", "Ebs": { "DeleteOnTermination": true, "VolumeSize": 20 } } ]' | tr -d \")
echo "Instance ID: $INSTANCE_ID"

DESTROY_CMD="aws $PROFILE ec2 terminate-instances --instance-ids $INSTANCE_ID"
echo "When you are done, please terminate your instance with:"
echo "$DESTROY_CMD"
echo "giving instance 90 seconds to wake up..."

sleep 90
echo "End creating EC2 instance"

PUBLIC_DNS=$(aws $PROFILE ec2 describe-instances --instance-ids $INSTANCE_ID --query "Reservations[*].Instances[*].[PublicDnsName]" --output text)
PUBLIC_IP=$(aws $PROFILE ec2 describe-instances --instance-ids $INSTANCE_ID --query "Reservations[*].Instances[*].[PublicIpAddress]" --output text)

USER_AT_HOST="$AWS_USER@${PUBLIC_DNS}"
echo "New instance created with ID \"$INSTANCE_ID\". To ssh into it:"
echo "ssh -i $PEM_FILE $USER_AT_HOST"

echo "Please wait at least 15 minutes while the branch \"$BRANCH\" from $REPO_URL is being deployed."

if [ -n "$GRPVRS" ]; then
  scp -i "$PEM_FILE" -o 'StrictHostKeyChecking no' -o 'UserKnownHostsFile=/dev/null' -o 'ConnectTimeout=300' "$GRPVRS" "$USER_AT_HOST:$GVFILE"
fi

ssh -T -i "$PEM_FILE" -o 'StrictHostKeyChecking no' -o 'UserKnownHostsFile=/dev/null' -o 'ConnectTimeout=300' "$USER_AT_HOST" <<EOF
sudo dnf -q -y install epel-release
sudo dnf -q -y install ansible git
git clone -b $DA_BRANCH https://github.com/GlobalDataverseCommunityConsortium/dataverse-ansible.git dataverse
export ANSIBLE_ROLES_PATH=.
ansible-playbook $VERBOSE_ARG -i dataverse/inventory dataverse/dataverse.pb --connection=local $GVARG
EOF

ssh-keyscan "${PUBLIC_DNS}" >> ~/.ssh/known_hosts
rsync -av -e "ssh -i $PEM_FILE" "$AWS_USER@$PUBLIC_DNS:/tmp/ansible_complete" ./

if [ -n "$LOCAL_LOG_PATH" ]; then
  echo "copying logs to $LOCAL_LOG_PATH."
  mkdir -p "$LOCAL_LOG_PATH"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/target/site" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/target/surefire-reports" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/mvn.out" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/target/coverage-it" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/target/coverage-reports/jacoco-unit.exec" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/target/jacoco_merged.exec" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/target/classes" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/opt/dataverse/dataverse/src" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/usr/local/payara*/glassfish/domains/domain1/logs/server.log*" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/tmp/query_count.out" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/tmp/dvinstall/install.out" "$LOCAL_LOG_PATH/"
  rsync -av -e "ssh -i $PEM_FILE" --ignore-missing-args "$AWS_USER@$PUBLIC_DNS:/tmp/dvinstall/setup-all.*.log" "$LOCAL_LOG_PATH/"
fi

CLICKABLE_LINK="http://${PUBLIC_DNS}"
echo "Branch $BRANCH from $REPO_URL has been deployed to $CLICKABLE_LINK"

if [ -z "$DESTROY" ]; then
  echo "To ssh into the new instance:"
  echo "ssh -i $PEM_FILE $USER_AT_HOST"
  echo "When you are done, please terminate your instance with:"
  echo "$DESTROY_CMD"
else
  echo "destroying AWS instance"
  eval "$DESTROY_CMD"
  echo "removing EC2 PEM"
  rm -f "$PEM_FILE"
fi