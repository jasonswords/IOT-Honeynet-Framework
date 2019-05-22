from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed #FileField the type of field, FileAllowed is a validator
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from IoT_Web.models import User
import boto3
import glob
import os
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)]) #name must be entered, Length() checks that the name exceed 2 characters and remain within 20
    email = StringField('Email', validators=[DataRequired(), Email()]) #email must be entered, Email() checks to see if the email is valid
    password = PasswordField('Password', validators=[DataRequired()]) #password must be entered
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')]) #password must be re-entered and must match the first password entered
    submit = SubmitField('Sign Up')

    def validate_username(self, username): #check if the username already exists in the db, and if it does show error message
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('The username is already taken')

    def validate_email(self, email): #check if the email already exists in the db, and if it does show error message
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('The email is already taken')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()]) #name must be entered, Length() checks that the name exceed 2 characters and remain within 20
    password = PasswordField('Password', validators=[DataRequired()]) #password must be entered
    remember = BooleanField('Remember Me') #stay logged in after closing browser, using secure cookies
    submit = SubmitField('Log In')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username: #if the new username entered is not the same as the current username then update the username
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email: #if the new email entered is not the same as the current email then update the email
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')




class InstanceStateForm(FlaskForm):

    submit1 = SubmitField('Start')
    submit2 = SubmitField('Stop')
    submit3 = SubmitField('Logs')
    submit4 = SubmitField('Terminate')


class StopInstance(FlaskForm):

    ec2 = boto3.resource('ec2')
    index = []
    value = []
    for instances in ec2.instances.all():
        index.append(instances.id)
        value.append(instances.id)

    instanceid = SelectField('Instance ID', choices=list(zip(index,value)),validators=[DataRequired()])
    submit = SubmitField('Stop Instance')

class StartInstance(FlaskForm):
    ec2 = boto3.resource('ec2')
    def compare_available_keys(*args, **kwargs):

        # Return a list of all keys available in the ssh-keys folder
        def get_key_names(*args, **kwargs):
            files = glob.glob("ssh-keys/*.pem")
            file_list = []
            for f in files:
                file_list.append(f.split('/')[1].split('.pem')[0])
            return file_list

        ec2 = boto3.client('ec2')
        # List key pairs and displays them to User
        index2 = []
        value2 = []

        keyPairs = ec2.describe_key_pairs()

        for key in range(0, len(keyPairs['KeyPairs'])):
            keyName = keyPairs['KeyPairs'][key]['KeyName']
            index2.append(keyName)
            value2.append(keyName)

        # empty list for available keys, locally and on aws
        keys_available = []
        keys = get_key_names()

        # Compare local keys to aws keys and add keys that exist in both places
        for x in keys:
            if x.split('.pem')[0] in index2:
                keys_available.append(x)
        # Return usable keys
        return keys_available

    index = []
    value = []
    for instances in ec2.instances.all():
        index.append(instances.id)
        value.append(instances.id)

    instanceid = SelectField('Instance ID', choices=list(zip(index, value)), validators=[DataRequired()])
    key_name = SelectField('Key Name', choices=list(zip(compare_available_keys(), compare_available_keys())), validators=[DataRequired()])
    submit = SubmitField('Start Instance')


class TerminateInstance(FlaskForm):
    ec2 = boto3.resource('ec2')
    index = []
    value = []
    for instances in ec2.instances.all():
        index.append(instances.id)
        value.append(instances.id)

    instanceid = SelectField('Instance ID', choices=list(zip(index, value)), validators=[DataRequired()])
    submit = SubmitField('Terminate Instance')

class ViewLogs(FlaskForm):

    ec2 = boto3.resource('ec2')
    client = boto3.client('logs')

    # List Log Groups.
    index_logGroup = []
    value_logGroup = []

    response2 = client.describe_log_groups()

    for logGroup in range(0, len(response2['logGroups'])):
        logGroupName = response2['logGroups'][0]['logGroupName']
        index_logGroup.append(logGroupName)
        value_logGroup.append(logGroupName)

    # List Private IP addresses of EC2 instances
    index_PrivateIP = []
    value_PrivateIP = []
    for instances in ec2.instances.all():
        index_PrivateIP.append(instances.private_ip_address)
        value_PrivateIP.append(instances.private_ip_address)

    # Form Select Fields
    logGroupName = SelectField('Log Group Name', choices=list(zip(index_logGroup,value_logGroup)))
    logFilter = SelectField('Private IP of Instance', choices=list(zip(index_PrivateIP,value_PrivateIP)))
    submit = SubmitField('Submit')

class CreateHoneypot(FlaskForm):
    # Return a list of keys available both locally and on aws...i.e.. usable keys
    def compare_available_keys(*args, **kwargs):

        # Return a list of all keys available in the ssh-keys folder
        def get_key_names(*args, **kwargs):
            files = glob.glob("ssh-keys/*.pem")
            file_list = []
            for f in files:
                file_list.append(f.split('/')[1].split('.pem')[0])
            return file_list

        ec2 = boto3.client('ec2')
        # List key pairs and displays them to User
        index2 = []
        value2 = []

        keyPairs = ec2.describe_key_pairs()

        for key in range(0, len(keyPairs['KeyPairs'])):
            keyName = keyPairs['KeyPairs'][key]['KeyName']
            index2.append(keyName)
            value2.append(keyName)

        # empty list for available keys, locally and on aws
        keys_available = []
        keys = get_key_names()

        # Compare local keys to aws keys and add keys that exist in both places
        for x in keys:
            if x.split('.pem')[0] in index2:
                keys_available.append(x)
        # Return usable keys
        return keys_available

    target = StringField('Target IP Address')
    cloneName = StringField('Docker Container Clone Name')
    ami_id_list = [('ami-02bcbb802e03574ba', 'Ohio'), ('ami-0f9ae750e8274075b', 'Tokyo-1'), ('ami-00a5245b4816c38e6', 'Tokyo-2'), ('ami-07683a44e80cd32c5', 'Ireland')]
    image_id = SelectField('Base Image ID', choices=ami_id_list, validators=[DataRequired()])
    instance_type = SelectField('Instance Type', choices=[('t2.micro', 't2.micro')], validators=[DataRequired()])
    key_name = SelectField('Key Name', choices=list(zip(compare_available_keys(), compare_available_keys())), validators=[DataRequired()])
    security_group_name = StringField('Security Group Name', validators=[DataRequired()])
    submit = SubmitField('Submit')



class CreateKeyPair(FlaskForm):
    keyName = StringField('SSH key name', validators=[DataRequired()])
    submit = SubmitField('Submit')

class CreateLogGroup(FlaskForm):
    name = StringField('Log Group Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

class CreateIAMPolicy(FlaskForm):

    iam = boto3.client('iam')

    index_user = []
    value_user = []

    # List users with the pagination interface
    paginator = iam.get_paginator('list_users')
    for response in paginator.paginate():
        u = response['Users']
        for user in u:
            index_user.append(user['UserName'])
            value_user.append(user['UserName'])

    iam_user = SelectField('IAM User', choices=list(zip(index_user, value_user)),
                           validators=[DataRequired()])

    role_name = StringField('Role Name', validators=[DataRequired()])
    policy_name = StringField('Policy Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

class CreateFlowLog(FlaskForm):
    ec2 = boto3.resource('ec2')
    # ec2 = boto3.resource('ec2')
    client = boto3.client('logs')
    client4 = boto3.client('ec2')
    client2 = boto3.client('iam')
    client3 = boto3.client('logs')

    # Three steps to enable logging.

    # Step One: select a role(policy) that allows the vpc to store logs in the log group.
    roles = client2.list_roles()

    index = []
    value = []

    Roles_list = roles['Roles']
    # Gets the arn for the policy we want to use.
    for key in Roles_list:
        # if key['RoleName'] == 'LoggingRole':
        role_name = key['RoleName']
        policyArn = key['Arn']
        value.append(role_name)
        index.append(policyArn)

    # End of Step One.

    # Step Two: List Log Groups and select one you would like your logs stored in.
    index_logGroup = []
    value_logGroup = []

    response2 = client.describe_log_groups()

    for logGroup in range(0, len(response2['logGroups'])):
        logGroupName = response2['logGroups'][logGroup]['logGroupName']
        index_logGroup.append(logGroupName)
        value_logGroup.append(logGroupName)

    # End of Step Two.

    # Step Three: Get the VPC we wish to use for flow logs.
    # Used to scope our results. Have to add a name to the vpc in order to filter for the vpc_id.

    index_vpc = []
    value_vpc = []

    filters = [{'Name': 'tag:Name', 'Values': ['*']}]

    vpcs = list(ec2.vpcs.filter(Filters=filters)) # retrieves list of VPC's
    vpc_list = {}  # stores vpc name and id.
    vpc_id = ''
    vpc_name = ''

    for vpc in vpcs:
        response = client4.describe_vpcs(
            VpcIds=[
                vpc.id,
            ]
        )

        name = response['Vpcs'][0]["Tags"][0]['Value']  # gets name of vpc from json dump.
        vpc_id = response['Vpcs'][0]["VpcId"]  # gets vpc id from json dump.

        dict = {name: vpc_id}  # temporary dictionary that is used to update vpc_list dictionary.
        vpc_list.update(dict)  # updates vpc_list dictionary.

        if vpc_list[name] == '':
            # changes the name of the vpc from being empty to having a value which is required.
            new_name = client.create_tags(Resources=[vpc_id],
                                      Tags=[{'Key': 'Name', 'Value': 'Default VPC'}])  # vpc name was originally test
            vpc_list.pop('')
            vpc_list['Default VPC'] = vpc_id
            vpc_name = 'Default VPC'
            index_vpc.append(vpc_name)
            value_vpc.append(vpc_id)

        index_vpc.append(name)
        value_vpc.append(vpc_id)

    # End of Step Three.

    role_name = SelectField('Role Name', choices=list(zip(index, value)), validators=[DataRequired()])
    log_group_name = SelectField('Log Group Name', choices=list(zip(index_logGroup, value_logGroup)))
    vpc_name = SelectField('VPC Name', choices=list(zip(value_vpc, index_vpc)))
    submit = SubmitField('Submit')


class Deploy_Honeypot(FlaskForm):
    path = os.path.abspath('scripts')
    dir_list = os.listdir(path)
    clone_list = []
    for d in dir_list:
        if '.' not in d:
            clone_list.append(d)

    def compare_available_keys(*args, **kwargs):

        # Return a list of all keys available in the ssh-keys folder
        def get_key_names(*args, **kwargs):
            files = glob.glob("ssh-keys/*.pem")
            file_list = []
            for f in files:
                file_list.append(f.split('/')[1].split('.pem')[0])
            return file_list

        ec2 = boto3.client('ec2')
        # List key pairs and displays them to User
        index2 = []
        value2 = []

        keyPairs = ec2.describe_key_pairs()

        for key in range(0, len(keyPairs['KeyPairs'])):
            keyName = keyPairs['KeyPairs'][key]['KeyName']
            index2.append(keyName)
            value2.append(keyName)

        # empty list for available keys, locally and on aws
        keys_available = []
        keys = get_key_names()

        # Compare local keys to aws keys and add keys that exist in both places
        for x in keys:
            if x.split('.pem')[0] in index2:
                keys_available.append(x)
        # Return usable keys
        return keys_available

    clone = SelectField('Choose Clone', choices=list(zip(clone_list,clone_list)), validators=[DataRequired()])
    ami_id_list = [('ami-02bcbb802e03574ba', 'Ohio'), ('ami-0f9ae750e8274075b', 'Tokyo-1'), ('ami-00a5245b4816c38e6', 'Tokyo-2'), ('ami-07683a44e80cd32c5', 'Ireland')]
    image_id = SelectField('Base Image ID', choices=ami_id_list, validators=[DataRequired()])
    instance_type = SelectField('Instance Type', choices=[('t2.micro', 't2.micro')], validators=[DataRequired()])
    key_name = SelectField('Key Name', choices=list(zip(compare_available_keys(), compare_available_keys())), validators=[DataRequired()])
    security_group_name = StringField('Security Group Name', validators=[DataRequired()])
    submit = SubmitField('Deploy Clone')

