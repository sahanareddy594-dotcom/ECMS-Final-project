// LOGIN FUNCTION
function loginUser() {
    var email = document.getElementById("email").value;
    var password = document.getElementById("password").value;

    if (email === "admin@gmail.com" && password === "1234") {
        alert("Login Successful");
        window.location.href = "dashboard.html";
    } else {
        alert("Invalid Login");
    }
}

// REGISTER FUNCTION
function registerUser() {
    alert("Registration Successful");
    window.location.href = "login.html";
}

// ADD MATERIAL
function addMaterial() {
    var name = document.getElementById("mname").value;
    var qty = document.getElementById("mqty").value;

    if (name === "" || qty === "") {
        alert("Enter all details");
        return;
    }

    var table = document.getElementById("materialTable");

    var row = table.insertRow();
    row.insertCell(0).innerHTML = name;
    row.insertCell(1).innerHTML = qty;
    row.insertCell(2).innerHTML = "Used";
    row.insertCell(3).innerHTML = "<button onclick='deleteRow(this)'>Delete</button>";
}

// DELETE ROW
function deleteRow(btn) {
    var row = btn.parentNode.parentNode;
    row.remove();
}