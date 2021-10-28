
  function mostrarContrasena(){
      const tipo = document.getElementById("contra");
      if(tipo.type == "password"){
          tipo.type = "text";
      }else{
          tipo.type = "password";
      }
  }
