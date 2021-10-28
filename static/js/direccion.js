const localizacion = document.querySelector('.location'); //click
const see = document.querySelector('.galeria') //agregar
const look = document.querySelector('.close') //salir


localizacion.addEventListener("click", () =>{
    see.classList.toggle("ubicacion");  
 
});




window.addEventListener('click', (e) =>{
   
    if(see.classList.contains("ubicacion") && e.target == look){
        see.classList.toggle("ubicacion");
        
    }
})