document.addEventListener('DOMContentLoaded', function() {
    const selectElement = document.getElementById('document-type');
    const reasonContainer = document.getElementById('reason-container');

    selectElement.addEventListener('change', function() {
        if (this.value === 'adeverinta_student') {
            reasonContainer.style.display = 'block';
        } else {
            reasonContainer.style.display = 'none';
        }
    });
});