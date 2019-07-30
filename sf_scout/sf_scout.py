import os, sys
import argparse, json, logging, coloredlogs
#sys.path.insert(0, "~/ScoutSuite/ScoutSuite")
#sys.path.insert(0, "~/Documents/SPACE/test/ScoutSuite/ScoutSuite/")

#from ScoutSuite.__main__ import run_from_cli

# Name of the role that is provisioned across all the Falcon Accounts
SCOUT_ROLE = "Scout"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('sf_scout')
coloredlogs.install(level='DEBUG', logger=logger)

'''
def runScout():
    return(run_from_cli())
'''

def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument("--acc-id",
                        dest="account_id",
                        default=None,
                        help="Account ID of the Service Team\'s Falcon Account (Trusting Account).")
    parser.add_argument("--id",
                        dest="id",
                        default=None,
                        help="This maps to the AWS_ACCESS_KEY_ID.")
    parser.add_argument("--key",
                        dest="key",
                        default=None,
                        help="This maps to the AWS_SECRET_ACCESS_KEY.")
    parser.add_argument("--token",
                        dest="token",
                        default=None,
                        help="This maps to the AWS_SESSION_TOKEN.")
    parser.add_argument("--rule",
                        dest="rule",
                        default=None,
                        help="This maps to the ruleset for Scout.")
    parser.add_argument("--sa",
                        dest="sa",
                        default="default",
                        help="This is the Security Assessment ID for the service.")
    parser.add_argument("--out",
                        dest="out",
                        default="default",
                        help="Output path of the report on the host.")
    args = parser.parse_args()

    return args

# Create the .aws/credentials file
def write_credentials(access_key_id, access_key, session_token, profile):

    creds = open("/home/scoutuser/.aws/credentials","w+")

    creds.write("["+profile+"]\n")

    if access_key_id is not None and access_key_id:
        creds.write("AWS_ACCESS_KEY_ID = " + access_key_id + "\n")
    if access_key is not None and access_key:
        creds.write("AWS_SECRET_ACCESS_KEY = " + access_key + "\n")
    if session_token is not None and session_token:
        creds.write("AWS_SESSION_TOKEN = " + session_token + "\n")

    creds.close()

def resource_teardown():
    os.remove("/home/scoutuser/.aws/credentials")
    if os.path.exists("temp.json"):
        os.remove("temp.json")

def main():

    logger.info("Running SF Scout")

    args = parse_args()
    args = args.__dict__

    aws_id=None
    aws_key=None
    aws_token=None
    rule=None
    acc_id=None
    sa=None

    # id corresponds to AWS_ACCESS_KEY_ID which cannot be empty. Logging a warning message here. Scout will handle the error.
    if args.get('id') is None:
        logger.warning("id is not set.")
    elif not str(args.get('id')):
        logger.warning("id is empty.")
    else:
        aws_id = str(args.get('id'))

    # key corresponds to AWS_SECRET_ACCESS_KEY which cannot be empty. Logging a warning message here. Scout will handle the error.
    if args.get('key') is None:
        logger.warning("key is not set.")
    elif not str(args.get('key')):
        logger.warning("key is empty.")
    else:
        aws_key = str(args.get('key'))

    # token corresponds to AWS_SESSION_TOKEN which can be empty when the credentials used are long lived credentials. Logging an info message here.
    if args.get('token') is None:
        logger.warning("token is not set.")
    elif not str(args.get('token')):
        logger.info("token is empty.")
    else:
        aws_token = str(args.get('token'))

    # rule corresponds to custom rule which scout will use. This can be empty when default ruleset is to be used. Logging an info message here.
    if args.get('rule') is None:
        logger.warning("rule is not set.")
    elif not str(args.get('rule')):
        logger.info("rule is empty.")
    else:
        rule = str(args.get('rule'))

    # account_id corresponds to the trusting account in AWS when assuming role. This can be empty when assume-role functionality is not to be used. Logging an info message here.
    if args.get('account_id') is None:
        logger.warning("account_id is not set.")
    elif not str(args.get('account_id')):
        logger.info("account_id is empty.")
    else:
        acc_id = str(args.get('account_id'))

    # sa corresponds to the SA number of the service for which Scout is being run. This should ideally not be empty. If the value is not set or empty then it defaults to "default".
    if args.get('sa') is None:
        logger.warning("sa is not set.")
    elif not str(args.get('sa')):
        logger.info("sa is empty.")
    else:
        sa = str(args.get('sa'))

    try:
        write_credentials(aws_id,
                            aws_key,
                            aws_token,
                            "default")

        if acc_id is not None and acc_id:

            ROLE_ARN = "arn:aws:iam::"+acc_id+":role/"+SCOUT_ROLE

            logger.info("Assuming role ["+SCOUT_ROLE+"] in account ["+acc_id+"]")
            os.system("aws sts assume-role --role-arn \""+ROLE_ARN+"\" --role-session-name \""+acc_id+"\" > temp.json")

            with open('temp.json') as json_file:
                data = json.load(json_file)


            credentials = data['Credentials']
            id = credentials['AccessKeyId']
            key = credentials['SecretAccessKey']
            token = credentials['SessionToken']

            write_credentials(id,
                                key,
                                token,
                                acc_id)

            scout_command = "python3 /ScoutSuite/scout.py aws --profile "+acc_id+" --report-dir=report/scout-report"

            if rule is not None and rule:
                logger.info("Using Rule - "+rule)

                scout_command = scout_command + " --ruleset=" + rule + ".json"
            else:
                logger.info("Using Rule - default")

            os.system(scout_command)
            resource_teardown()
        else:

            scout_command = "python3 /ScoutSuite/scout.py aws --profile default --report-dir=report/scout-report"

            if rule is not None and rule:
                logger.info("Using Rule - "+rule)

                scout_command = scout_command + " --ruleset=" + rule + ".json"
            else:
                logger.info("Using Rule - default")

            os.system(scout_command)
            resource_teardown()

        if os.path.exists("report/scout-report"):
            logger.info("Zipping files")
            os.system("zip -r -m report/"+sa+".zip report/scout-report")
            logger.info("Zipping complete.")
            logger.info("Zipped files will be found at the following location on the host : "+str(args.get('out')))
        else:
             raise Exception("ScoutSuite encountered an error.")
    except Exception as e:
        logger.info("Exception occured.")
        logger.error(e)
        logger.info("Reports not produced.")

    # TODO : This is a better approach. Check why this is not working
    '''
    ROLE_ARN = "arn:aws:iam::"+str(args.get('account_id'))+":role/"+SCOUT_ROLE
    creds = open("/Users/pmatharoo/.aws/config","w+")

    creds.write("[profile temp]\n")

    creds.write("role_arn = " + ROLE_ARN + "\n")
    creds.write("source_profile = default\n")
    creds.close()
    '''

    #sys.exit(run_from_cli())
    #return(run_from_cli())

if __name__== "__main__":

    main()


#############################################################
#
# Different approach to solving the same problem.
#
# Scenario 1: Advisory owns the execution of ScoutSuite
#
#
# Scenario 2: Service owner owns the execution of ScoutSuite
#
#
#
# '''
# Approach 1:
# call os.system() and pass parameters from our script
# '''
# os.system("python3 ~/ScoutSuite/scout.py aws ")
# input()
#
# '''
# Approach 2:
# Add the path of Scout into our script and call Scout functions
#
# Advanatge - CLI params remain the same. No need to define it again
# '''
#
#
#
#
#
