import logging
from superset.security import SupersetSecurityManager

class CustomSsoSecurityManager(SupersetSecurityManager):

    def oauth_user_info(self, provider, response=None):
        logging.debug("Oauth2 provider: {0}.".format(provider))
        if provider == 'open_id_provider':
            # Request the userinfo endpoint and retrieve user details as a JSON object
            me = self.appbuilder.sm.oauth_remotes[provider].get('userinfo')
            
            # Check for successful response status
            if me.status_code == 200:
                logging.debug("User data response: {0}".format(me.text))
                
                # Parse the response as JSON
                data = me.json()
                logging.info("me.json() %s", data)
               
                full_name = data.get('name', '')
                name_parts = full_name.split()
                first_name = name_parts[0] if name_parts else ''
                last_name = name_parts[-1] if len(name_parts) > 1 else ''
                # Return the relevant user data from the parsed JSON
                return {
                    'phone': data.get('phone_number', ''),
                    'email': data.get('email', ''),
                    'id': data.get('username', ''),
                    'username': data.get('username', ''),
                    'name': full_name,
                    'first_name': first_name,
                    'last_name': last_name
                    }
            else:
                logging.error("Error fetching user info: {0}".format(me.status_code))
                return {}
        return {}


