/*
* Enclave client side javascript
*/

/**
 * Shows the Enclave banner
 */
function showEnclaveBanner(){
    let cookieBanner = document.getElementsByClassName("nk-enclave-banner")[0];
    cookieBanner.style.display = "block";
}

/**
 * Hides the Cookie banner and saves the value to localstorage
 */
function clickEnclaveBanner(){

    console.log("clicked on accept enclave");
    let enclavebutton = document.getElementById("enclavebutton");
    enclavebutton.innerHTML = " <i class=\"fa fa-circle-o-notch fa-spin\"></i> Initializing";
    startEnclave()
}

/**
 * Checks the localstorage and shows Cookie banner based on it.
 */
function initializeEnclaveBanner(){


    document.getElementById("bar").style.height =
        200 + "px";
    document.getElementById("status").innerHTML = "0.0";


    showEnclaveBanner();
}

var extensionID = "fcdgmdjfeepbhmjhifoeaeaegejjcnel";


function killEnclave(){
    chrome.runtime.sendMessage(extensionID, {disconnect : true}, null);
}
function startEnclave(){
    chrome.runtime.sendMessage(extensionID, {loadenclave : true}, function(response) {
        let enclavebutton = document.getElementById("enclavebutton");
        enclavebutton.innerHTML = "&#10004;\t Initialized";
        enclavebutton.classList.replace("btn-primary","btn-success")
    });
    console.log("Enclave loaded");
}


function sendToEnclave(wasmCode,cb) {
    console.log("I am about to send the request to the Extension");
    fetch(wasmCode)
        .then(response => response.text())
        .then((data) => {
            let fullwasm = data.split("\n");
            chrome.runtime.sendMessage(extensionID, {message: "runWebAssembly", wasmcode: fullwasm[0],authtag: fullwasm[1]},cb);
        });

    console.log("I sent the request to the Extension");
}

// Assigning values to window object
window.onload = initializeEnclaveBanner();
window.nk_clickEnclaveBanner = clickEnclaveBanner;
