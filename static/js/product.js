const hamburguer = document.querySelector(".m");
const menu = document.querySelector(".menu-navegacion");



hamburguer.addEventListener("click", () =>{
    menu.classList.toggle("spread");  
 
});



window.addEventListener("click", e => {
    // console.log(menu.classList.contains("spread") && e.target != menu && e.target != hamburguer)
    
    if(menu.classList.contains("spread") && e.target != menu && e.target != hamburguer){
        menu.classList.toggle("spread");
    }

});