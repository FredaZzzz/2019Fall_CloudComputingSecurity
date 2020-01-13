function sendCredentials(){
	var username = document.getElementById("username").value;
	var password = document.getElementById("password").value;
	var obj = {username:username, password:password};
	var xhr = new XMLHttpRequest();
	xhr.open("GET", 'login', true);
	xhr.setRequestHeader('Content-Type', 'application/json');
	xhr.responseType = 'document';
	xhr.onload = function () {
  		if (xhr.status=='200'){
  			location.href = '/index';
  			
  		}
  		else
  			alert("Login credentials does not match");
	};
	xhr.send(JSON.stringify(obj));
	//console.log(xhr.responseText);
	/*var msg = 'username: ' + username + '    password: ' + password;
	alert(msg);*/
	
	//location.href = '/index';//arbitrarily sets the url
	
}
