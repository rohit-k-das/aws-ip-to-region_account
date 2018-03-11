import boto3
import os

def account(profile,ip,private=False):
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
				
				    if private:
					print  
					break
				    else:				    
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

#Santize IP
def sanitize_ip(ip):
	numbers = ip.split('.')
	if len(numbers) == 4:
		for i in numbers:
			try:
				if not (int(i) >= 0 and int(i) < 256):
					print 'ERROR: ' + ip + ' is not a valid IP address'
					return False
			except Exception, e:
				if 'invalid literal for int()' in e.message:
					print 'ERROR: ' + ip + ' is not an IP address'
					return False
	else:
		return False

	if ip == '0.0.0.0':
		return False
	elif ip == '255.255.255.255':
		return False
	
	return True

#Check if IP is private IP
def check_private_ip(ip):
	numbers = ip.split('.')
	if numbers[0] == '10':
		return True
	elif numbers[0] == '192' and numbers[1] == '168':
		return True
	elif numbers[0] == '172' and int(numbers[1]) >= 16 and int(numbers[1]) <= 31:
		return True

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
    if sanitize_ip(ip):
	ip = ip.split('.')
	count = 0
	for i in ip:
		ip[count] = int(i)
		count = count + 1
	ip = '.'.join(['%s' % str(i) for i in ip])
	
	print "Searching " + ip + " accross accounts " + str(profile_names) + " ...."
    	for profile in profile_names:
		try:
			if check_private_ip(ip):
				account(profile,ip,check_private_ip(ip))
		
    			else:
				if account(profile,ip,check_private_ip(ip)):
        				break
		except Exception,e:
			if 'AccessDenied' in e.message:
				print 'ERROR: Lack of permissions to access AWS IAM for account ' + profile + ' .'
				print
			else:
                		print 'ERROR: ' + e.message
				print
    else:
	exit(1)
    
	
	

if __name__ == '__main__':
    main()

