document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('callsignInput');
    const btn = document.getElementById('createBtn');

    btn.addEventListener('click', () => {
        const callsign = input.value.trim().toUpperCase();
        
        if(callsign.length < 3) {
            alert("Please enter a valid Organization or Callsign (min 3 chars).");
            return;
        }

        // Save Identity
        localStorage.setItem('CHAOS_CALLSIGN', callsign);
        
        // Visual Feedback
        btn.innerText = "Securing Identity...";
        btn.style.background = "#10b981"; // Success Green

        // Redirect to Dashboard after 1 second
        setTimeout(() => {
            window.location.href = '/dashboard.html';
        }, 800);
    });

    // Allow "Enter" key
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') btn.click();
    });
});
