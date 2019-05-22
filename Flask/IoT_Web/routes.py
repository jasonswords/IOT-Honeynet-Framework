import os
import subprocess
import secrets
import boto3
import json
from PIL import Image
from flask import flash, render_template, redirect, url_for, request, abort #importing IoT_Web module and creating IoT_Web web server from the IoT_Web module
from IoT_Web import app, db, bcrypt
from IoT_Web.forms import RegistrationForm, LoginForm, UpdateAccountForm, InstanceStateForm, StopInstance, ViewLogs, StartInstance, TerminateInstance, CreateHoneypot, CreateKeyPair, CreateLogGroup, CreateIAMPolicy, CreateFlowLog, Deploy_Honeypot
from IoT_Web.models import User
from flask_login import login_user, current_user, logout_user, login_required
from botocore.exceptions import ClientError
import time

@app.route("/") #specifies the default page
@app.route("/home", methods=['GET', 'POST'])
def home(): #when the user goes to the default page they will be representded with the home page if they go to the login or register page
    return render_template('home.html')

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/register", methods=['GET', 'POST'])
@login_required
def register():
    form = RegistrationForm()
    if current_user.id == 1:
        if form.validate_on_submit(): #after submiting a register form
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8') #hash the password and decode it into string
            user = User(username=form.username.data, email=form.email.data, password=hashed_password) #username and email will remain in plaintext format, password will be hashed
            db.session.add(user) #adding new user to the database
            db.session.commit() #commiting this change to the database
            flash('Your account was successfully created', 'success') #show message Account created for + username of the account created if successful (success category)
            return redirect(url_for('login')) #after successfully creating an account redirect the user to the home page
        return render_template('register.html', form=form)
    else:
        redirect(url_for('home'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: #if the current user is authenticated then redirect them to the home page
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit(): #after logging in
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data): #if the user exists and the password that they entered is valid and checks with the password in the db then the user can login
            login_user(user, remember=form.remember.data) #log the user in, and allow the remember the user option
            next_page = request.args.get('next') #if the user is not logged in and is trying to access a page that you must be logged in for, the user will be redirected to the login page and after they successfully login they will be directed to the page they were trying to go instead of the default home page
            return redirect(next_page) if next_page else redirect(url_for('home')) #redirect the user to the next_page url parameter if the next_page parameter exists, else redirect to the home page, this is known as a turnary conditional
        else:
         flash('Unsuccessful login!', 'danger') #danger bootstrap category
    return render_template('login.html', form=form)

@app.route("/logout") #logout the user and return them to the home page
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8) #changing the uploaded images name to a random generated name
    _, f_ext = os.path.splitext(form_picture.filename) #discarding the original image file name and holding on to the file extension for the purpose of storing it in the db
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)

    output_size = (200, 200) # image resizing, resize the image that the user uploads, saves space on the filesystem and speeds up the websites loading time
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required #need to login to access this page
def account():
    form = UpdateAccountForm() #creating an instance of UpdateAccountForm
    if form.validate_on_submit():
        if form.picture.data:
           picture_file = save_picture(form.picture.data)
           current_user.image_file = picture_file
        current_user.username = form.username.data #updating users username
        current_user.email = form.email.data #updating users email
        db.session.commit() #commiting these changes to the db
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username #populating the users field with their current username
        form.email.data = current_user.email #populating the users field with their current email
    image_file = url_for('static', filename='images/' + current_user.image_file) #specifying where the default user profile picture is located,
    return render_template('account.html', image_file=image_file, form=form) #passing the image file and form to the account.html file


@app.route("/HoneyPotList")
def HoneyPotList():
    ec2 = boto3.resource('ec2') # Create the ec2 resource object
    form = InstanceStateForm()
    return render_template('HoneyPotList.html', ec2=ec2, form=form) # make ec2 available in html page

@app.route("/start_instance", methods=['POST','GET'])
def start_instance():
    form = StartInstance()
    if form.validate_on_submit():
        try:
            path = os.path.abspath('scripts')
            ssh_key = form.key_name.data
            ec2 = boto3.resource('ec2')
            instance_id =  ec2.Instance(form.instanceid.data)

            if instance_id.state != 'terminated':
                flash('Instance starting', 'success')
                instance_id.start()
                instance_id.wait_until_running()
                instance_id.load()
                flash('Waiting on instance to start', 'success')
                time.sleep(60)
                flash('Instance running', 'success')
                pub_dns = instance_id.public_dns_name

                try:
                    subprocess.run(['bash', path + '/restart_clone.sh', pub_dns, ssh_key + '.pem'])
                    flash('Clone is starting now', 'success')
                except Exception as e:
                    print(e)
                    flash('Error restarting clone, maybe the key is incorrect', 'danger')
            else:
                flash('This instance is terminated, it cannot be started', 'danger')
                return render_template('start_instance.html', form=form)

        except Exception as e:
            print(e)
            flash('Error starting instance', 'danger')

        return redirect(url_for('HoneyPotList'))

    return render_template('start_instance.html', form=form)



@app.route("/stop_instance", methods=['POST','GET'])
def stop_instance():
    form = StopInstance()
    if form.validate_on_submit():
        try:
            ec2 = boto3.resource('ec2')
            ec2.Instance(form.instanceid.data).stop()
            flash('Instance stopping', 'success')
        except Exception as e:
            flash('Error stopping instance', 'danger')
        return redirect(url_for('HoneyPotList'))
    return render_template('stop_instance.html', form=form)

@app.route("/terminate_instance", methods=['POST','GET'])
def terminate_instance():
    form = TerminateInstance()
    if form.validate_on_submit():
        try:
            ec2 = boto3.resource('ec2')
            ec2.Instance(form.instanceid.data).terminate()
            flash('Terminating instance {} '.format(form.instanceid.data), 'success')
        except Exception as e:
            flash('Error terminating instance', 'danger')
        return redirect(url_for('HoneyPotList'))
    return render_template('terminate_instance.html', form=form)

@app.route("/display_logs", methods=['POST','GET'])
def display_logs():

    return render_template("display_logs.html")

@app.route("/view_logs", methods=['POST','GET'])
def view_logs():
    form = ViewLogs()

    path = os.path.abspath('Logging')

    if form.validate_on_submit():
        try:
            ec2 = boto3.resource('ec2')
            client = boto3.client('logs')
            # log streams.
            response = client.describe_log_streams(
                logGroupName=form.logGroupName.data
            )

            log_stream_name = []

            for logStream in range(0, len(response['logStreams'])):
                logStreamName = response['logStreams'][logStream]['logStreamName']
                log_stream_name.append(logStreamName)

            # Filter Log messages.
            response3 = client.filter_log_events(
                logGroupName=form.logGroupName.data,
                logStreamNames=log_stream_name,
                filterPattern=form.logFilter.data
            )

            message = []

            # Loop through json object
            for log in response3['events']:
                message.append(log['message'].split(' '))

            if message:
                return render_template('display_logs.html', logs=message)
            else:
                flash('No logs are available', 'danger')
                render_template('view_logs.html', form=form)
        except Exception as e:
            flash('An Error occured displaying this page', 'danger')
    return render_template('view_logs.html', form=form)

@app.route("/create_honeypot", methods=['POST','GET'])
def create_honeypot():
    form = CreateHoneypot()

    if form.validate_on_submit():


        # get absolute path to scripts directory
        path = os.path.abspath('scripts')

        clone = form.cloneName.data.lower()
        clone_name = clone.replace(" ", "_")

        # Check if port 22 will be in file... must be included for ssh
        def check_for_port_22():
            val = '22'
            # open file and read into list
            with open(path + '/ports.txt', 'r') as p:
                list_values = [port.rstrip() for port in p]
            # Check if port 22 is in ports.txt file
            if val not in list_values:
                # Add port 22 to text file if not already there
                with open(path + '/ports.txt', 'a') as w:
                    w.write('22')\
                # Add extra tcp protocol to protocols.txt
                with open(path + '/protocols.txt', 'a') as w:
                    w.write('tcp')

        flash('Please be patient, the scan can take a long time', 'success')
        # execute bash script to scan ip and make required files from the results
        subprocess.run(['bash', path + '/clone.sh' , form.target.data, clone_name])

        check_for_port_22()

        ec2 = boto3.resource('ec2')
        sg = boto3.client('ec2')
        vpc = boto3.client('ec2')

        permissions = []

        f = open(path + "/ports.txt", "r")
        f1 = f.readlines()

        t = open(path + "/protocols.txt", "r")
        t1 = t.readlines()

        for x in range(len(f1)):
            permissions.append({'IpProtocol': t1[x].rstrip(), 'FromPort': int(f1[x]), 'ToPort': int(f1[x]),
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})

        response = vpc.describe_vpcs()
        vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

        try:
            security = form.security_group_name.data
            security_group = security.replace(" ", "_")

            response = ec2.create_security_group(GroupName= security_group, #form.security_group_name.data,
                                             Description='This is a security group for {} honeypot'.format(clone_name),
                                             VpcId=vpc_id)

            securityGroups = sg.describe_security_groups()

            security_group_dict = {}

            security_list = []

            for names in range(0, len(securityGroups['SecurityGroups'])):
                groupName = securityGroups['SecurityGroups'][names]['GroupName']
                groupId = securityGroups['SecurityGroups'][names]['GroupId']
                dict = {groupName: groupId}
                security_group_dict.update(dict)

            for name in security_group_dict:
                if name == security_group:
                    security_list.append(security_group_dict[name])


            data = sg.authorize_security_group_ingress(
                GroupId=security_list[0],
                IpPermissions=permissions
            )

            # 2. create the instance
            try:
                instance = ec2.create_instances(
                    # ImageID specifies the Amazon Machine Image (AMI) ID of the instance we want to create.
                    ImageId=form.image_id.data,
                    # MinCount and MaxCount are used to define the number of EC2 instances to launch.
                    MinCount=1,
                    MaxCount=1,
                    # InstanceType is the size of the instance, like t2.micro, t2.small, or m5.large.
                    InstanceType=form.instance_type.data,
                    # KeyName defines the name of the key pair that will allow access to the instance. We generate
                    # this key-pair in the Create Key Pair python script.
                    KeyName=form.key_name.data,
                    SecurityGroupIds=security_list
                )

                # wait until newly created instance is in running state
                instance[0].wait_until_running()

                # reload the instance values
                instance[0].load()

                # put public dns of new instance in variable
                pub_dns = instance[0].public_dns_name


                print('Sleeping')
                # Give instance time to boot completely
                time.sleep(60)

                # Call bash script to transfer and execute files from cloned device
                try:
                    flash('Transfering files and starting clone', 'success')
                    subprocess.run(['bash', path + '/transfer_files.sh' , form.key_name.data + '.pem', pub_dns, clone_name])
                except Exception as e:
                    flash('Files failed to transfer', 'danger')
                    return render_template('create_honeypot.html', form=form)

            except Exception as e1:
                flash('Invalid AM ID, please check the region the account is in', 'danger')
                return render_template('create_honeypot.html', form=form)

        except Exception as e2:
            print(e2)
            flash('This security group name already exists', 'danger')
            return render_template('create_honeypot.html', form=form)

        return redirect(url_for('HoneyPotList'))

    return render_template('create_honeypot.html', form=form)


@app.route("/create_keypair_page", methods=['POST','GET'])
def create_keypair_page():
    form = CreateKeyPair()
    path = os.path.abspath('ssh-keys')
    # Place key name in variable with additional formatting...No spaces and lower case
    if form.validate_on_submit():
        try:
            ec2 = boto3.resource('ec2')
            ssh_key = form.keyName.data
            ssh_key_name = ssh_key.replace(" ", "_")

            # call the boto ec2 function to create a key pair
            key_pair = ec2.create_key_pair(KeyName=ssh_key_name)

            # capture the key and store it in a file
            KeyPairOut = str(key_pair.key_material)

            with open(path + "/" + ssh_key_name + '.pem', 'w') as w:
                w.write(KeyPairOut)

            flash('Key successfully created', 'success')

            # return redirect(url_for('create_log_group'))

        except Exception as e:
            flash('Key name already exists, please try an alternative name', 'danger')
            return render_template("/create_keypair_page.html", form=form)

        return redirect(url_for('create_log_group'))

    return render_template("/create_keypair_page.html", form=form)


@app.route("/configuration_page", methods=['POST','GET'])
def configuration_page():

    return render_template("configuration_page.html")

@app.route("/create_log_group", methods=['POST','GET'])
def create_log_group():

    form = CreateLogGroup()

    if form.validate_on_submit():
        client = boto3.client('logs')
        try:
            response = client.create_log_group(
                logGroupName=form.name.data # Log Group Name
                )
            flash('Log group crteated successfully', 'success')
        except Exception as e:
            flash('Problem creating log group', 'danger')
            return render_template("/create_log_group.html", form=form)

        return redirect(url_for('create_iam_policy'))

    return render_template("/create_log_group.html", form=form)

@app.route("/create_iam_policy", methods=['POST','GET'])
def create_iam_policy():
    form = CreateIAMPolicy()

    if form.validate_on_submit():
        client = boto3.client('iam')

        # Function to check if role already exists before continuing
        def is_user_available(user):
            roles = client.list_roles()
            role_list = roles['Roles']
            for role_name in role_list:
                if role_name['RoleName'] == user:
                    return True
            return False
        role_name = form.role_name.data.replace(" ", "_")
        policy_name = form.policy_name.data.replace(" ","_")

        # check if role name is available before continuing
        if not is_user_available(role_name):
            try:

                try:
                    trustPolicy = '{ "Version": "2012-10-17", "Statement": [ { "Sid": "", "Effect": "Allow", "Principal": { "Service": "vpc-flow-logs.amazonaws.com" }, "Action": "sts:AssumeRole" } ] }'
                    response = client.create_role(
                        RoleName=role_name,  # Role name.
                        AssumeRolePolicyDocument=trustPolicy,
                        # trust relationship that allows the flow logs service to assume the role.
                        Description='This is an IAM role for logging.'
                    )
                except Exception as e1:
                    flash('Error.. Role {} already exists'.format(role_name), 'danger')

                # This is the flow log IAM policy.
                flowLogIAMPolicy = '{ "Version": "2012-10-17", "Statement": [ { "Action": [ "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams" ], "Effect": "Allow", "Resource": "*" } ] } '

                # Creates a policy for logging permissions.
                response1 = client.create_policy(
                    PolicyName=policy_name,
                    PolicyDocument=flowLogIAMPolicy
                )

                arnPolicy = response1['Policy']['Arn']  # This retrieves the arn policy from the policy I created above.

                # This attaches the policy to the new role we created.
                response2 = client.attach_role_policy(
                    RoleName=role_name,  # Name of policy.
                    PolicyArn=arnPolicy  # This is the policy that allows the flow log to publish to the the log group.
                )

                response = client.attach_user_policy(
                    UserName=form.iam_user.data,
                    PolicyArn=arnPolicy
                )
                flash('The operation has completed successfully', 'success')

            except Exception as e1:
                flash('Error.. Policy "{}" already exists'.format(policy_name), 'danger')
                return render_template("/create_iam_policy.html", form=form)
        else:
            flash('Error.. Role "{}" already exists'.format(role_name), 'danger')
            return render_template("/create_iam_policy.html", form=form)

        return redirect(url_for('create_flow_log'))

    return render_template("/create_iam_policy.html", form=form)

@app.route("/create_flow_log", methods=['POST', 'GET'])
def create_flow_log():

    form = CreateFlowLog()

    if form.validate_on_submit():
        try:
            client = boto3.client('ec2')

            response = client.create_flow_logs(
                DeliverLogsPermissionArn=form.role_name.data,  # what policy is used.
                LogGroupName=form.log_group_name.data,  # name of log Group created.
                ResourceIds=[form.vpc_name.data],  # vpc id.
                ResourceType='VPC',
                TrafficType='ALL',  # what traffic to log
                LogDestinationType='cloud-watch-logs',  # what destination log type to use (Cloud Watch Logs or S3 Bucket)
                # LogDestination=log_groups_dict['TestLogGroup']
            )
            flash('The operation has completed successfully', 'success')
        except Exception as e:
             flash('Error creating flow logs', 'danger')
             return render_template("/create_flow_log.html", form=form)

        return redirect(url_for('create_honeypot'))

    return render_template("/create_flow_log.html", form=form)


@app.route("/deploy_honeypot", methods=['POST', 'GET'])
def deploy_honeypot():

    form = Deploy_Honeypot()

    if form.validate_on_submit():
        path = os.path.abspath('scripts')
        ec2 = boto3.resource('ec2')
        sg = boto3.client('ec2')
        vpc = boto3.client('ec2')
        clone_name = form.clone.data

        permissions = []
        try:
            f = open(path + '/' + clone_name + "/ports.txt", "r")
            f1 = f.readlines()

            t = open(path + '/' + clone_name  + "/protocols.txt", "r")
            t1 = t.readlines()

            if '22' not in f1:
                f1.append('22')
                t1.append('tcp')

            for x in range(len(f1)):
                permissions.append({'IpProtocol': t1[x].rstrip(), 'FromPort': int(f1[x]), 'ToPort': int(f1[x]),
                                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})
        except FileNotFoundError as e:
            flash('Text file not found', 'danger')

        response = vpc.describe_vpcs()
        vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

        try:
            security = form.security_group_name.data
            security_group = security.replace(" ", "_")

            response = ec2.create_security_group(GroupName= security_group, #form.security_group_name.data,
                                             Description='This is a security group for {} honeypot'.format(clone_name),
                                             VpcId=vpc_id)

            securityGroups = sg.describe_security_groups()

            security_group_dict = {}

            security_list = []

            for names in range(0, len(securityGroups['SecurityGroups'])):
                groupName = securityGroups['SecurityGroups'][names]['GroupName']
                groupId = securityGroups['SecurityGroups'][names]['GroupId']
                dict = {groupName: groupId}
                security_group_dict.update(dict)

            for name in security_group_dict:
                if name == security_group:
                    security_list.append(security_group_dict[name])


            data = sg.authorize_security_group_ingress(
                GroupId=security_list[0],
                IpPermissions=permissions
            )

            # 2. create the instance
            try:
                instance = ec2.create_instances(
                    # ImageID specifies the Amazon Machine Image (AMI) ID of the instance we want to create.
                    ImageId=form.image_id.data,
                    # MinCount and MaxCount are used to define the number of EC2 instances to launch.
                    MinCount=1,
                    MaxCount=1,
                    # InstanceType is the size of the instance, like t2.micro, t2.small, or m5.large.
                    InstanceType=form.instance_type.data,
                    # KeyName defines the name of the key pair that will allow access to the instance. We generate
                    # this key-pair in the Create Key Pair python script.
                    KeyName=form.key_name.data,
                    SecurityGroupIds=security_list
                )

                # wait until newly created instance is in running state
                instance[0].wait_until_running()

                # reload the instance values
                instance[0].load()

                # put public dns of new instance in variable
                pub_dns = instance[0].public_dns_name


                print('Sleeping')
                # Give instance time to boot completely
                time.sleep(60)

                # Call bash script to transfer and execute files from cloned device
                try:
                    flash('Transfering files and starting clone', 'success')
                    subprocess.run(['bash', path + '/transfer_files.sh' , form.key_name.data + '.pem', pub_dns, clone_name])
                except Exception as e:
                    flash('Files failed to transfer', 'danger')
                    return render_template('deploy_honeypot.html', form=form)

            except Exception as e1:
                flash('Invalid AM ID, please check the region the account is in', 'danger')
                return render_template('deploy_honeypot.html', form=form)

        except Exception as e2:
            print(e2)
            flash('This security group name already exists', 'danger')
            return render_template('deploy_honeypot.html', form=form)

        return redirect(url_for('HoneyPotList'))

    return render_template('deploy_honeypot.html', form=form)
