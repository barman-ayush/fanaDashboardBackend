document.getElementById('setup-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const formData = new FormData(this);

    // Show loading overlay and disable submit button
    document.getElementById('loading-overlay').style.display = 'flex';
    const submitButton = this.querySelector('button[type="submit"]');
    submitButton.disabled = true;

    fetch('/fanaCall/', {
        method: 'POST',
        headers: {
            'X-CSRFToken': formData.get('csrfmiddlewaretoken')
        },
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerText = data.status === 'success' ? 'Setup completed successfully!' : `Error: ${data.message}`;
        // Hide loading overlay and enable submit button
        document.getElementById('loading-overlay').style.display = 'none';
        submitButton.disabled = false;
    })
    .catch(error => {
        document.getElementById('response').innerText = `Error: ${error}`;
        // Hide loading overlay and enable submit button
        document.getElementById('loading-overlay').style.display = 'none';
        submitButton.disabled = false;
    });
});
