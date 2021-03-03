const crypto = require('crypto')
const fetch = require("node-fetch");

class GuardianKey {

     constructor(gk_conf) {
      this.organization_id = gk_conf['organization_id']
      this.authgroup_id = gk_conf['authgroup_id']
      this.key = gk_conf['key']
      this.iv = gk_conf['iv']
      this.service = gk_conf['service']
      this.agentId = gk_conf['agentId']
      this.api_url = 'https://api.guardiankey.io/v2/checkaccess'
    }
    
    check_access(client_ip,user_agent,username,useremail,login_failed) {
      let event     = this.create_event(client_ip,user_agent,username,useremail,login_failed);
      let event_str = JSON.stringify(event);

      let hash = crypto.createHash('sha256').update(event_str+this.key+this.iv).digest('hex');
      
      // JSON to submit to the GK's API
      let jsonmsg = {"id": this.authgroup_id, "message": event_str, "hash": hash };

      let content = JSON.stringify(jsonmsg);
      let headers = {'Content-type': 'application/json', 'Accept': 'text/plain'};
     
      const init = { method: 'POST', headers: headers, body: content };
      const response = fetch(this.api_url, init).then(res => res.json());
      return response
    }

    create_event(client_ip,user_agent,username,useremail,login_failed) {
      let event = {     "generatedTime":  Math.trunc(Date.now()/1000),
                        "agentId":        this.agentId,
                        "organizationId": this.organization_id,
                        "authGroupId":    this.authgroup_id,
                        "service":        this.service,
                        "clientIP":       client_ip,
                        "clientReverse":  "",
                        "userName":       username,
                        "authMethod":     "",
                        "loginFailed":    login_failed,
                        "userAgent":      user_agent,
                        "psychometricTyped": "",
                        "psychometricImage": "",
                        "event_type":     "Authentication", // Must leave it in this case!
                        "userEmail":      useremail
                }
      return event
    }
}

module.exports = GuardianKey
