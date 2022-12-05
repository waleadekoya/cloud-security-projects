import base64
import json
from datetime import datetime
from pprint import pprint
from typing import Optional, Dict, Any, Union

import boto3
import botocore.exceptions


class RotateAccessKey:

    def __init__(self,
                 role_to_assume: str,
                 iam_user: str,
                 secret_name: str,
                 region_code: str,
                 ):
        self.role_to_assume = role_to_assume
        self.secret_name = secret_name
        self.sts: Optional[boto3.client] = boto3.client('sts')
        self.region_name = region_code
        self.secret_client = boto3.client('secretsmanager', region_name=self.region_name)
        self.assume_role()
        self.iam_user: str = iam_user
        self.update_secret_details()

    def assume_role(self):
        # Call the assume_role method of the STSConnection object and pass the role
        # ARN and a role session name
        assumed_role_object = self.sts.assume_role(
            RoleArn=self.role_to_assume,
            RoleSessionName="UpdateSecretKeyRoleSession"
        )
        print(self.sts.get_caller_identity())
        print(assumed_role_object['AssumedRoleUser'])

    def get_secret_value_response(self) -> Dict[str, Any]:
        """
        Function to retrieve secret value from specified secret name in secrets manager
        """
        try:
            print("Fetching the details for the secret name {}".format(self.secret_name))
            response = self.secret_client.get_secret_value(SecretId=self.secret_name)
            secret = response['SecretString'] if 'SecretString' in response \
                else base64.b64decode(response['SecretBinary'])
            return json.loads(secret)
        except botocore.exceptions.ClientError as error:
            response = error.response
            raise Exception(response['Error']['Message'])

    def create_new_access_key(self, client):
        """
        Creates a new AWS secret access key and corresponding AWS access key ID for the specified user
        """
        response: Dict[str, Dict[str, Union[str, datetime]]] = client.create_access_key(UserName=self.iam_user)
        return response['AccessKey']

    @staticmethod
    def get_dictionary_key_for_access_key(secret: dict) -> str:
        if "AKIA" in list(secret.values()):
            return [key for key, value in secret if "AKIA" in value][0]
        return ""

    def update_secret_details(self):
        # current_secret = self.get_secrets()
        current_secret: Dict[str, Any] = self.get_secret_value_response()
        access_map_key: str = self.get_dictionary_key_for_access_key(current_secret)
        if access_map_key == "":
            raise Exception(f"Access key not found in secret values stored with secret name: {self.secret_name}")

        iam_client = boto3.client('iam')
        for access_key in iam_client.list_access_keys(UserName=self.iam_user)['AccessKeyMetadata']:
            current_access_key = access_key.get(access_map_key)
            if current_access_key == current_secret[access_map_key]:
                pprint(access_key)
                print("current access key is being deleted...")
                iam_client.delete_access_key(
                    UserName=self.iam_user,
                    AccessKeyId=access_key.get(access_map_key)
                )
                print(f"successfully deleted access key id \'{current_access_key}\'\n")
        new_access_key = self.create_new_access_key(iam_client)
        current_secret[access_map_key] = new_access_key['AccessKeyId']
        current_secret['SecretAccessKey'] = new_access_key['SecretAccessKey']

        secret_client = boto3.client('secretsmanager')
        response = secret_client.update_secret(
            SecretId=self.secret_name,
            SecretString=json.dumps(current_secret, default=str)
        )
        pprint(response)
        print("new secret is:")
        pprint(current_secret)


# RotateAccessKey()
