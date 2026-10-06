# Cortex Cloud XQL example authentication

Copy/paste versions of every XQL query used by the scripts are collected in
[`XQL-queries.md`](XQL-queries.md).

The Python examples in this directory authenticate to the Cortex Cloud XQL
public API with the following three values:

| Environment variable | Value sent by the examples | Where to find or create it in Cortex Cloud |
| --- | --- | --- |
| `CORTEX_API_URL` | The tenant API base URL, such as `https://api-yourfqdn` | Use your tenant's API FQDN in place of `api-yourfqdn`. The XQL API documentation uses that value as the base of its request URL. Do not append `/public_api/v1`; the scripts append the API paths themselves. |
| `CORTEX_API_KEY` | The API key secret in the `Authorization` header | Go to **Settings → Configurations → Integrations → API Keys → New Key**, select a role that is allowed to run XQL, generate the key, and copy it before closing the dialog. Cortex does not display the secret again after the dialog closes. |
| `CORTEX_API_KEY_ID` | The key's ID in the `x-xdr-auth-id` header | Go to **Settings → Configurations → Integrations → API Keys** and copy the **ID** for the same key from the API Keys inventory. |

The examples use the direct-header form required by the XQL APIs:

```text
Authorization: <CORTEX_API_KEY>
x-xdr-auth-id: <CORTEX_API_KEY_ID>
```

For this simple direct-header implementation, create a Standard API key. If
your tenant requires an Advanced API key, use Cortex's documented signing /
authentication procedure for that key type instead of sending its secret as a
plain header value.

Set the values in the shell without putting them in source control:

```bash
export CORTEX_API_URL="https://api-yourfqdn"
export CORTEX_API_KEY="paste-the-generated-key-here"
export CORTEX_API_KEY_ID="12345"
```

Optional for MSSP requests: set `CORTEX_TENANT_ID` to the child or local tenant
ID to place it in the XQL request's `tenants` list. Leave it unset for a single
local tenant.

The API key must have the RBAC permissions for XQL and access to the datasets
being queried; licensing and dataset permissions are enforced by Cortex Cloud.

References:

* [Start an XQL query](https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud-Platform-APIs/Start-an-XQL-query)
* [Get XQL query results](https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud-Platform-APIs/Get-XQL-query-results)
* [Create a new API key](https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud-Platform-APIs/Create-a-new-API-key)
