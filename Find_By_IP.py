import boto3
import os

def account(profile,ip):
	session = boto3.session.Session(profile_name = profile)
	regions = session.get_available_regions('ec2')

	for region in regions:
		client = session.client('ec2',region_name = region)
		response = client.describe_addresses()
                for address in response['Addresses']:
                    if address:
                        try:
                            if 'PrivateIpAddress' in address or 'PublicIp' in address:
                                if ip == address['PrivateIpAddress']:
                                    print 'Profile:' + profile
				    print 'Region: ' + region
				    if address['Tags']:
					for tag in address['Tags']:
						if tag['Key'] == 'Name':
							print 'Instance Name: ' + tag['Value']
							break
				    if 'InstanceId' in address:
					print 'Instance Id: ' + address['InstanceId']
				    if 'NetworkInterfaceId' in address:
					print 'Network Interface Id: ' + address['NetworkInterfaceId']
                                    if 'PublicIp' in address:
					print 'Public IP: ' + address['PublicIp']  
				    return True

				if ip == address['PublicIp']:
				    print 'Profile:' + profile
				    print 'Region: ' + region
				    if address['Tags']:
					for tag in address['Tags']:
						if tag['Key'] == 'Name':
							print 'Instance Name: ' + tag['Value']
							break
				    if 'InstanceId' in address:
					print 'Instance Id: ' + address['InstanceId']
				    if 'NetworkInterfaceId' in address:
					print 'Network Interface Id: ' + address['NetworkInterfaceId']
				    if 'PrivateIpAddress' in address:
					print 'Private IP: ' + address['PrivateIpAddress']
				    return True
                        except:
                            pass

#Get all AWS account profiles from aws credentials file
def get_profiles(cred_file):
    profiles = []
    try:
        with open(cred_file) as f:
            for line in f.readlines():
                if '[' in line:
                    line = line.replace('[','').replace(']','').strip('\n')
                    profiles.append(line)
    except Exception,e:
        print "Error:" +str(e)
    return profiles

#Get default home dir of user executing the script
def get_home_dir():
    current_user_id = os.getuid()
    with  open('/etc/passwd') as passwd_file:
        for line in passwd_file.readlines():
            field = line.split(':')
            if current_user_id == int(field[2]):
                home_dir = field[5]
    return home_dir

def main():
    home_dir = get_home_dir()
    cred_file_path = home_dir + '/.aws/credentials'

    #Checks if aws credential file exists and get all AWS account profiles
    if os.path.exists(cred_file_path):
        profile_names = get_profiles(cred_file_path)
    else:
        cred_file_path = raw_input("Please enter credential files absolute path: ")
        profile_names = get_profiles(cred_file_path)

    #Enter IP address to be searched across multiple accounts and regions
    ip = raw_input("Enter IP Address: ")
    print "Searching " + ip + " accross accounts " + str(profile_names) + " ...."
    for profile in profile_names:
        if account(profile,ip):
        	break

if __name__ == '__main__':
    main()

