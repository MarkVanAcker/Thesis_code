var port = null;
var callbackFunction =null;

function onDisconnected() { 
  port = null;
}
  
function disconnect(){
  port.disconnect();
}

function sendNativeMessage(message) {
  port.postMessage(message);
}

function onNativeMessage(message) {
  console.log("Listener triggered");
  console.log( "result: " + message.res);
  if(callbackFunction){
   callbackFunction({"data":message});
  }
  console.log("Success message sent to the webpage");
  //keep connection open, messages don't arrive all at the same time.
  //disconnect();
}


//connect to the host and start Remote Attestation.
function connect() {
  var hostName = "com.mark.wasm_enclave";
  port = chrome.runtime.connectNative(hostName);
  port.onMessage.addListener(onNativeMessage);
  port.onDisconnect.addListener(onDisconnected);
}



chrome.runtime.onMessageExternal.addListener(
  function(request, sender, sendResponse) {
          console.log("Request received from the webpage");

  if (request.loadenclave){
      connect();
      console.log("enclave loaded");
  }
  if(request.disconnect){
      disconnect();
      console.log("disconnected enclave");
  }
  if (request.wasmcode)
  {
      console.log("Everything OK");
      chrome.browserAction.setBadgeText({text: "OK"});
      if (!port){
           console.log("connecting with enclave...");
           connect();
      }

      if (port){
	console.log(request);
        sendNativeMessage(request);
        console.log("Message sent to host application");
      }
      else{
        console.log("Port closed, message not sent to host");
      }
  }
  callbackFunction=sendResponse;
  console.log("True sent to the webpage");
  return true;
});
console.log("Ready in the background");

