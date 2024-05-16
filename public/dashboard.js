// Frontend JavaScript to handle logout
document.getElementById('logoutButton').addEventListener('click', function() {
    // Clear the authentication token stored in local storage
    localStorage.removeItem('accessToken');
    
    // Redirect the user to the login page
    window.location.href = '/login';
});
