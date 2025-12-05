window.addEventListener("load", () => {
    updateHeaderForAuthState();
});

function updateHeaderForAuthState() {
    const isLoggedIn = localStorage.getItem("userLoggedIn") === "true";
    const userName = localStorage.getItem("userName") || null;
    const userRole = localStorage.getItem("userRole") || null;

    // Elementos del header
    const navUsername = document.getElementById("nav-username");
    const navUserIcon = document.getElementById("nav-user-icon");
    const navMiProgresoDesktop = document.getElementById("nav-miprogreso-desktop");
    const navMiProgresoMobile = document.getElementById("nav-miprogreso-mobile");
    const logoutButtonContainer = document.getElementById("logout-button-container");

    if (!isLoggedIn) {
        navUsername && navUsername.classList.add("hidden");
        navMiProgresoDesktop && navMiProgresoDesktop.classList.add("hidden");
        navMiProgresoMobile && navMiProgresoMobile.classList.add("hidden");

        if (navUserIcon) {
            navUserIcon.href = "/login";
            navUserIcon.title = "Iniciar Sesión";
        }

        if (logoutButtonContainer) logoutButtonContainer.innerHTML = "";

        return; // 👉 Salimos porque no hay sesión
    }

    if (navUsername) {
        navUsername.textContent = userName ? userName.split(" ")[0] : "Usuario";
        navUsername.classList.remove("hidden");
    }

    if (navUserIcon) {
        const dashboardUrl =
            userRole === "admin" ? "/dashboard/admin" :
            userRole === "instructor" ? "/dashboard/instructor" :
            "/dashboard/student";

        navUserIcon.href = dashboardUrl;
        navUserIcon.title = "Mi Dashboard";
    }

    navMiProgresoDesktop && navMiProgresoDesktop.classList.remove("hidden");
    navMiProgresoMobile && navMiProgresoMobile.classList.remove("hidden");
    
    if (logoutButtonContainer) {
        logoutButtonContainer.innerHTML = `
            <button id="logout-btn" class="bg-red-500 hover:bg-red-600 text-white font-semibold py-1 px-3 text-sm rounded transition duration-200 ml-4">
                Cerrar Sesión
            </button>
        `;

        document.getElementById("logout-btn").addEventListener("click", async () => {
            await fetch("/api/auth/logout", { method: "POST" });
            
            localStorage.clear();

            window.location.href = "/login";
        });
    }
}
