const user = document.querySelector('.usuario') //click
const seee = document.querySelector('.fondo21') //agregar
const cl = document.querySelector('.closek') //salir

user.addEventListener("click", () =>{
    seee.classList.toggle("fondo2121");  //clase que sera agregada a seee
 
});


window.addEventListener('click', (e) =>{
   
    if(seee.classList.contains("fondo2121") && e.target == cl ){
        seee.classList.toggle("fondo2121");
        
    }
})

