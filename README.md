<p>
  <img src="https://cyberuslabs.com/wp-content/uploads/2015/09/cl_new_logo-e1553199321586.png" alt="Cyberus Key logo">
</p>

# How to install

```bash
pip install cyberuskey
```

or you can clone repository and use CyberusKey class directly in your project 
# Usage Example

```python
from cyberuskey.cyberuskey import CyberusKey
from cyberuskey.exceptions import AuthenticateException

class AuthenticationHandler:
    def get(self):   
        cyberus = CyberusKey(
        'CLIENT_ID',
        'CLIENT_SECRET',
        'REDIRECT_URI')
        
        arguments = self.request.arguments
        try:
            id_token_data, access_token = cyberus.authorize(arguments)
        except AuthenticateException as exc:
            self.write(exc.error_description)
            self.set_status(401)
            raise exc
...
```

## Links

CyberusKey docs: http://loginwithoutpasswords.com/docs/  
CyberusKey widget: https://github.com/CyberusLabs/cyberuskey-widget

# License
[MIT](LICENSE.md) © Cyberus Labs sp. z o.o.

