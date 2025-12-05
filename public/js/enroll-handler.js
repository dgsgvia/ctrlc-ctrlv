
function handleEnrollClick(courseId, courseTitle) {
  const token = localStorage.getItem("token")
  const userRole = localStorage.getItem("userRole")

  if (!token) {
    window.location.href = "/login.html"
    return
  }

  if (userRole !== "student") {
    alert("Solo los estudiantes pueden inscribirse en cursos")
    return
  }

  if (!confirm(`¿Deseas inscribirte al curso "${courseTitle}"?`)) {
    return
  }

  fetch("/api/enroll", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ courseId }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.message) {
        alert(data.message)
        // Redirect to student dashboard
        window.location.href = "/dashboard/student"
      } else {
        alert("Error: " + (data.error || "No se pudo inscribir al curso"))
      }
    })
    .catch((error) => {
      console.error("[v0] Enrollment error:", error)
      alert("Error al procesar la inscripción")
    })
}

window.enrollCourse = handleEnrollClick
