/**
 * CSRF Protection for AJAX requests
 * This file adds CSRF token to all AJAX requests automatically
 */
$(function() {
    // Get the CSRF token from a meta tag
    var token = $("meta[name='_csrf']").attr("content");
    var header = $("meta[name='_csrf_header']").attr("content");
    
    // Add CSRF token to all AJAX requests
    $(document).ajaxSend(function(e, xhr, options) {
        if (header && token) {
            xhr.setRequestHeader(header, token);
        }
    });
});
