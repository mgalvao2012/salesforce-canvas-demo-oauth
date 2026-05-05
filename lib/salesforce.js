var axios = require('axios').default;

async function getAccountName(recordId, envelope) {
  const url = `${envelope.client.instanceUrl}${envelope.context.links.sobjectUrl}Account/${recordId}?fields=Name`;
  const headers = {
    Authorization: `Bearer ${envelope.client.oauthToken}`,
    'Content-Type': 'application/json',
  };
  const response = await axios.get(url, { headers });
  return response.data.Name;
}

module.exports = { getAccountName };
