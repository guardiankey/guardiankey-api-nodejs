
const GuardianKey = require('./guardiankey.js');

// GK configuration. ATTENTION: the first 4 fields can be found in the GK's panel -> authgroup -> deploy tab
const gk_conf = { "organization_id": "",
                  "authgroup_id": "",
                  "key": "",
                  "iv":  "",
                  "service": "MySystem", // rarely needed. Keep as is 
                  "agentId": "MyAgentId" // rarely needed. Keep as is
              }

let gk = new GuardianKey(gk_conf);

client_ip = "1.1.1.1"; // the client's IP address
username = "teste@teste.com"; // username
useremail = username; // user email
login_failed = 0; // 0 if pass match; 1 if login failed
// This is the user-agent sent by the client, ex request.headers.get('user-agent')
user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36";

(async() => {
  let gk_return = {}
  try { // Good practice: Always use it inside a try-catch!
    gk_return = await gk.check_access(client_ip,user_agent,username,useremail,login_failed)
  }catch(e){
    gk_return = {"response": "ERROR"}
  }
  console.log(gk_return['response'])
})();

/*

Information about the GK's return
=================================
    gk_return['response'] may be:
        ACCEPT -> just allow access attempt
        BLOCK  -> block access attempt
        NOTIFY -> allow access attempt and notify the user. This notification can occur in the GK's API side. See the authgroup conf in panel
        HARD_NOTIFY -> allow access attempt, notify the user and *may* require an extra step, for example a 2nd factor.
        
        # EXCEPTIONS
        TIMEOUT         -> if processing took too long time (>4s)
        ERROR           -> something wrong with the sent information
        SETTING_MISSING -> something wrong with the sent information
      
    Return example:    
      { "response": "ACCEPT",       
          "response_cache": "0",        // If 1, you may cache the response for this client IP for 30m
          "message": "",                // Some output from the core engine
          "risk": "0.1",                // Total attack risk, from 0 to 100
          "risk_psychometric": "0.1",   // psychometric part
          "risk_intel": "0.1",          // intel part
          "risk_context": "0.1",        // context part
          "eventId": "c9259ce0415f33e03bb9deb0a03b7114ec4fd69c6ed49876a7db34da54edb25f",      // Used to interact with API
          "event_token": "83d95363ffc0e959312d2f21640b821ee0c89253a6d4a6f32dede571fd032599",  // Key to interact with API for this event id
          "generatedTime": "1614721293", // timestamp UTC for
          "client_ua": "Firefox",  // Browser used by the user
          "client_os": "Linux",    // OS used by the user
          "country": "Brazil"      // Contry, origin of client access
        }
   
Example 
=======
        1. User submit username and pass
        2. Verify if username/pass are valid (yes or no)
        3. Call gk.check_access, in any case
        4. If gk_return['response'] == 'BLOCK', block the access attempt.
           Allow the access in any other case!

   
Dependencies
============
    # npm i node-fetch --save

*/

