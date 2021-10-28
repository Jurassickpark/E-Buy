const imagenes = document.querySelector('.img-galerial') //salir
const imagen1 = document.querySelector('.sitemap')  //click
const gal = document.querySelector('.galeriamap')  //agregar


/* imagen1.addEventListener("click", () =>{
    alert('vamos');
 
});
 */

imagen1.addEventListener("click", () =>{

    gal.classList.toggle('show')

 
});

gal.addEventListener('click', (e) =>{
    // console.log(e.target)
    // console.log(e.target !== imagenes)
   

    if(e.target !== imagenes){
        gal.classList.toggle("show");
        
    }
})