// Navbar js
document.addEventListener("DOMContentLoaded", function(){
const toggleMenu=()=>{
    const navigation = document.querySelector(".navgation");
    const menuIcon =document.querySelector(".menu_icon")
navigation.classList.toggle("navgation--mobile");
const isMenu = navigation.classList.contains("navgation--mobile");
menuIcon.src = isMenu ? "/static/img/close.png" : "/static/img/menu.png";
}
document.querySelector(".menu_icon_button").addEventListener("click",toggleMenu)
});

 // Rate us
 let stars = document.getElementsByClassName("star");
    
 function star(n) {
     remove();
     for (let i = 0; i < n; i++) {
         let cls = "";
         switch(n) {
             case 1: cls = "one"; break;
             case 2: cls = "two"; break;
             case 3: cls = "three"; break;
             case 4: cls = "four"; break;
             case 5: cls = "five"; break;
             default: cls = "";
         }
         stars[i].className = "star " + cls;
     }
     // Store rating in the database
     storeRating(n);
 }
 
 function remove() {
     for (let i = 0; i < stars.length; i++) {
         stars[i].className = "star";
     }  
 }
 
 function storeRating(rating) {
     fetch('/submit_rating', {
         method: 'POST',
         headers: {
             'Content-Type': 'application/json'
         },
         body: JSON.stringify({ rating: rating })
     })
     .then(response => response.json())
     .then(data => {
         if (data.success) {
             console.log('Rating submitted successfully');
             alert('Thank you for your rating!');
         } else {
             console.error('Error submitting rating:', data.message);
             alert('There was an error submitting your rating.');
         }
     })
     .catch(error => {
         console.error('Fetch error:', error);
         alert('There was an error submitting your rating.');
     });
 }

setTimeout(function() {
        var flashMessages = document.querySelectorAll('.flash-message');
        flashMessages.forEach(function(message) {
            message.style.display = 'none';
        });
    }, 5000);