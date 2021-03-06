function listURLBuilder(url, list){
  var file = document.getElementById(list+"_Import").value.trim();
  var force = "";
  if (file != ""){
    if (document.getElementById(list+"_ForceImport").checked == true){
      force = "f";
    }else{
      force = "df";
    }
    postURL(url, force, file)
  }else{
    alert('Please select a file');
  }
}
function whitelistImport(){
  listURLBuilder("/admin/whitelist/import", 'wl');
}
function whitelistExport(){
  listURLBuilder("/admin/whitelist/export", 'wl');
}
function dropWhitelist(){
  if(confirm("You are about to drop the whitelist. Are you sure?")){
    var url = "/admin/whitelist/drop";window.location = url;
  }
}
function blacklistImport(){ 
  listURLBuilder("/admin/blacklist/import", 'bl');
}
function blacklistExport(){
  listURLBuilder("/admin/blacklist/export", 'bl');
}
function dropBlacklist(){
  if(confirm("You are about to drop the whitelist. Are you sure?")){
    var url = "/admin/blacklist/drop";window.location = url;
  }
}

function postURL(url, force, file) {
  var form = document.createElement("FORM");
  form.method = "POST";
  form.style.display = "none";
  document.body.appendChild(form);
  form.action = url
  inputForce = document.createElement("INPUT");
  inputForce.type = "hidden";
  inputForce.name = "force"
  inputForce.value = force
  form.appendChild(inputForce);
  inputFile = document.createElement("INPUT");
  inputFile.type = "hidden";
  inputFile.name = "file"
  inputFile.value = file
  form.appendChild(inputFile);
  form.submit();
}
