function preParseDate(datestr){
  /**
   * Convert a string of date to an array.
   * Add year to datestr with format "mm-dd".
   * This function is separated from the parseDate(datestr) function 
   * in order for postEvent() function to validate the format of input date.
   * @param {datestr} var A string in the format of "yyyy-mm-dd" or "mm-dd"
   * @return {arr} array The converted array [y,m,d]
   */
  var arr = datestr.split('-');
  if(arr.length == 2){ //arr[0]=month, arr[1]=date
    var today = new Date();
    if(today.getMonth()+1 > arr[0] || 
      (today.getMonth()+1 == arr[0] && today.getDate() > arr[1])){
      arr.unshift(today.getFullYear() + 1);
    }
    else arr.unshift(today.getFullYear());
  }
  else if(arr.length != 3)//arr[0]=year, arr[1]=month, arr[2]=date
    return [-1,-1,-1];
  return arr;
}


function parseDate(datestr) {
  /**
   * With reference to the instruction document.
   * Convert a string of date to the Date object.
   * @param {datestr} var A string in the format of "yyyy-mm-dd" or "mm-dd"
   * @return {Date} obj The converted Date object
   */
  var arr = preParseDate(datestr);//arr[0]=year, arr[1]=month, arr[2]=date
  return new Date(Number.parseInt(arr[0]), Number.parseInt(arr[1]-1), Number.parseInt(arr[2]));
}


function getRemainingTime(datestr){
  /**
   * Takes in a date (in string with format "yyyy-mm-dd" or "mm-dd"),
   *  calculates the time left until that date, 
   *  and return the count down (in string with format "xxdays xxhrs xxmins xxsecs").
   * @param {datestr} var A string in the format of "yyyy-mm-dd" or "mm-dd"
   * @return {str} A string indicating the time interval
   */
  var date = parseDate(datestr);
  let seconds = Math.floor((+date - new Date()) / 1000);
  if (seconds<0) return "Expired";
  var days2go = parseInt(seconds/86400, 10);
  var rest = seconds % 86400;
  var hours2go = parseInt(rest/3600, 10);
  rest = rest % 3600;
  var mins2go = parseInt(rest/60,10);
  rest = rest % 60;
  var secs2go = rest;
  return `${days2go}days ${hours2go}hrs ${mins2go}mins ${secs2go}secs`;	
}


function postEvent(){  
  /**
   * Read event name and event date from html input,
   *  send to server via XMLHttpRequest()
   *  by making a POST request to url '/event'.
   *  Allow duplication. 
   */
  var x = document.getElementById("frm1");
  var arr = preParseDate(x.elements[1].value);
  var date = parseDate(x.elements[1].value);
  if (date.getFullYear() != arr[0]
    || date.getMonth()!= arr[1]-1
    || date.getDate()!=arr[2]){
    alert("Invalid Date Format");
    return False;
    }
  var obj = {name:x.elements[0].value, date:x.elements[1].value};
  var Json = JSON.stringify(obj);
  var xmlhttp = new XMLHttpRequest();   
  var url = "event";
  xmlhttp.open("POST", url);
  xmlhttp.setRequestHeader("Content-Type", "application/json");
  xmlhttp.send(JSON.stringify(Json));
  //get_events();//attemp to reload events after modification, but unstable
}


function reqJSON(method, url, payload) {
  /**
   * Taken from instruction document.
   * Sends a request to server and store the result in ${data} 
   * ${data} is expected to be json. 
   * @param {method} string Such as "POST" or "GET"
   * @param {url} string Such as "/" or "/events"
   * @param {payload} string The payload to send to the server
   */
  return new Promise((resolve, reject) => {
    let xhr = new XMLHttpRequest();
    xhr.open(method, url);
    xhr.responseType = 'json';
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve({status: xhr.status, data: xhr.response});
      } else {
        reject({status: xhr.status, data: xhr.response});
      }
    };
    xhr.onerror = () => {
      reject({status: xhr.status, data: xhr.response});
    };
    xhr.send(payload);
  });
}


//document.addEventListener('DOMContentLoaded', get_events());


function get_events(){
  /**
   * Taken from instruction document.
   * Loading the event information from server 
   *  by making a GET request to url '/events' 
   */
  var path = window.location.pathname;
  var page = path.split("/").pop();
  reqJSON('GET', 'events')
  .then(({status, data}) => {
    let html = '<tr><th> Event Name </th><th> Event Date </th><th> Count Down </th></tr>';
    var rowIndex=1;
    for (let event of data.events) {
      var str = getRemainingTime(event.date);
      if(str == "Expired")continue;
      //added button for deletion
      var button = `<td><button type='button' onclick='delete_event(${rowIndex})'>delete</button></td>`;
      html += `<tr><td> ${event.name} </td><td> ${event.date} </td><td> ${str} </td>${button}</tr>`;
      rowIndex++;
    }
    document.getElementById('list').innerHTML = html;
  })
  .catch(({status, data}) => {
    // Display an error.
    document.getElementById('events').innerHTML = 'ERROR: ' + JSON.stringify(data);
  });
}


function delete_cookie(){
  /**
   * Clear the current cookie
   */
  document.cookie="login_cookie=; expires= Thu, 01 Jan 1970 00:00:00 GMT ; domain=.amiable-reducer-251721.appspot.com; path=/";
}


function delete_event(rowIndex){
  /**
   * When a delete button is pressed,
   *  delete content of this line, identified by row number
   *  by making a POST request to url '/event'.
   */
  var table = document.getElementById('list');
  var name = table.rows[rowIndex].cells[0].innerText;
  var date = table.rows[rowIndex].cells[1].innerText;
  var obj = {name:name, date:date};
  var Json = JSON.stringify(obj);
  var xmlhttp = new XMLHttpRequest();   
  var url = "event";
  xmlhttp.open("DELETE", url);
  xmlhttp.setRequestHeader("Content-Type", "application/json");
  xmlhttp.send(JSON.stringify(Json));
  
  //get_events();//attemp to reload events after modification, but unstable
}


function set_oidc_info(){
  var cookies = document.cookie.split("; ");
  var i;
  var str;
  for(i=0;i<cookies.length;i++){
    if(cookies[i].indexOf("oidc_cookie")>=0){
      str = cookies[i];
      break;
    }
  }
  str = str.replace(/\\054/g, ',');
  str = str.replace(/\\/g, '');
  str = str.substring(13,str.length-1);
  var oidc_info = JSON.parse(str);
  document.getElementById('response_type').value = oidc_info.response_type;
  document.getElementById('scope').value = oidc_info.scope;
  document.getElementById('client_id').value = oidc_info.client_id;
  document.getElementById('state').value = oidc_info.state;
  document.getElementById('nonce').value = oidc_info.nonce;
  document.getElementById('redirect_uri').value = oidc_info.redirect_uri;
}
   
