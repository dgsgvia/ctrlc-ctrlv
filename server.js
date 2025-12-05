const express = require("express")
const mysql = require("mysql2/promise")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const cors = require("cors")
const path = require("path")
require("dotenv").config()

const app = express()
const PORT = process.env.PORT || 3000

app.use(
  cors({
    origin: true,
    credentials: true,
  }),
)
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "public")))

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "lu_learning",
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
})

pool
  .getConnection()
  .then((connection) => {
    console.log("Conectado a la base de datos lu_learning")
    connection.release()
  })
  .catch((err) => {
    console.error("Database connection failed:", err.message)
  })

const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_jwt_key"

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1]

  if (!token) {
    return res.status(401).json({ error: "Acceso no autorizado. Token no proporcionado." })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido o expirado." })
    }
    req.user = user
    next()
  })
}

const authorizeRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "No tienes permisos para acceder a este recurso.",
        requiredRole: allowedRoles,
        yourRole: req.user?.role,
      })
    }
    next()
  }
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"))
})

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"))
})

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"))
})

app.get("/courses", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "courses.html"))
})

app.get("/courses/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "course-detail.html"))
})

app.get("/forgot-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "forgot-password.html"))
})

app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset-password.html"))
})

app.get("/dashboard/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard-admin.html"))
})

app.get("/dashboard/instructor", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard-instructor.html"))
})

app.get("/dashboard/student", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard-student.html"))
})

app.get("/lessons/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "lesson.html"))
})

app.get("/quiz/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "quiz.html"))
})

app.get("/quiz-results/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "quiz-results.html"))
})

app.post("/api/auth/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password, role } = req.body

    if (!firstName || !lastName || !email || !password || !role) {
      return res.status(400).json({ error: "Todos los campos son obligatorios." })
    }

    if (!email.endsWith("@lulearning.com")) {
      return res.status(400).json({
        error: "Solo se permiten correos con dominio @lulearning.com",
      })
    }

    if (!["student", "instructor"].includes(role)) {
      return res.status(400).json({
        error: 'Rol inválido. Solo se permite "student" o "instructor".',
      })
    }

    const [existingUsers] = await pool.query("SELECT id FROM users WHERE email = ?", [email])

    if (existingUsers.length > 0) {
      return res.status(409).json({
        error: "El correo electrónico ya está registrado.",
      })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const employeeId = "EMP" + Date.now().toString().slice(-6)

    const [result] = await pool.query(
      `INSERT INTO users (employee_id, email, password, first_name, last_name, role, hire_date, is_active)
       VALUES (?, ?, ?, ?, ?, ?, CURDATE(), TRUE)`,
      [employeeId, email, hashedPassword, firstName, lastName, role],
    )

    res.status(201).json({
      message: "Usuario registrado exitosamente.",
      userId: result.insertId,
      role: role,
    })
  } catch (error) {
    console.error("Error en registro:", error)
    res.status(500).json({ error: "Error al registrar usuario." })
  }
})

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son obligatorios." })
    }

    if (!email.endsWith("@lulearning.com")) {
      return res.status(400).json({
        error: "Solo se permiten correos con dominio @lulearning.com",
      })
    }

    const [users] = await pool.query(
      "SELECT id, email, password, first_name, last_name, role, is_active FROM users WHERE email = ?",
      [email],
    )

    if (users.length === 0) {
      return res.status(401).json({ error: "Credenciales inválidas." })
    }

    const user = users[0]

    if (!user.is_active) {
      return res.status(403).json({ error: "Cuenta desactivada. Contacta al administrador." })
    }

    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Credenciales inválidas." })
    }

    await pool.query("UPDATE users SET last_login = NOW() WHERE id = ?", [user.id])

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name,
      },
      JWT_SECRET,
      { expiresIn: "24h" },
    )

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000,
    })

    res.json({
      message: "Inicio de sesión exitoso.",
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
      },
      token,
    })
  } catch (error) {
    console.error("Error en login:", error)
    res.status(500).json({ error: "Error al iniciar sesión." })
  }
})

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token")
  res.json({ message: "Sesión cerrada exitosamente." })
})

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, employee_id, email, first_name, last_name, role, department, position FROM users WHERE id = ?",
      [req.user.id],
    )

    if (users.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado." })
    }

    res.json({ user: users[0] })
  } catch (error) {
    console.error("Error obteniendo usuario:", error)
    res.status(500).json({ error: "Error al obtener información del usuario." })
  }
})

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ error: "El correo electrónico es obligatorio." })
    }

    if (!email.endsWith("@lulearning.com")) {
      return res.status(400).json({
        error: "Los correos válidos deben pertenecer a la empresa y terminar en @lulearning.com.",
      })
    }

    const [users] = await pool.query("SELECT id FROM users WHERE email = ?", [email])

    const code = Math.floor(100000 + Math.random() * 900000).toString()

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000)

    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.headers["user-agent"] || ""

    if (users.length > 0) {
      await pool.query(
        `INSERT INTO password_resets (email, code, expires_at, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?)`,
        [email, code, expiresAt, ipAddress, userAgent],
      )

      console.log(`[PASSWORD-RESET] email: ${email} — CODE: ${code} — expires_at: ${expiresAt.toISOString()}`)
    }

    res.json({
      message:
        "Si el correo existe, se ha generado un código de recuperación. Revisa el registro del servidor en el entorno local.",
    })
  } catch (error) {
    console.error("Error requesting password reset:", error)
    res.status(500).json({ error: "Error al solicitar recuperación de contraseña." })
  }
})

app.post("/api/auth/verify-reset", async (req, res) => {
  try {
    const { email, code } = req.body

    if (!email || !code) {
      return res.status(400).json({ error: "Email y código son obligatorios." })
    }

    if (!email.endsWith("@lulearning.com")) {
      return res.status(400).json({
        error: "Los correos válidos deben pertenecer a la empresa y terminar en @lulearning.com.",
      })
    }

    const [resets] = await pool.query(
      `SELECT * FROM password_resets
       WHERE email = ? AND code = ? AND used = FALSE AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [email, code],
    )

    if (resets.length === 0) {
      return res.status(400).json({ error: "Código inválido o expirado." })
    }

    const reset = resets[0]

    const resetToken = jwt.sign({ email, resetId: reset.id }, JWT_SECRET, { expiresIn: "10m" })

    await pool.query("UPDATE password_resets SET reset_token = ? WHERE id = ?", [resetToken, reset.id])

    res.json({
      message: "Código verificado exitosamente.",
      resetToken,
    })
  } catch (error) {
    console.error("Error verifying reset code:", error)
    res.status(500).json({ error: "Error al verificar código." })
  }
})

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body

    if (!resetToken || !newPassword) {
      return res.status(400).json({ error: "Token y nueva contraseña son obligatorios." })
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." })
    }

    let decoded
    try {
      decoded = jwt.verify(resetToken, JWT_SECRET)
    } catch (err) {
      return res.status(400).json({ error: "Token inválido o expirado." })
    }

    const [resets] = await pool.query(
      `SELECT * FROM password_resets
       WHERE id = ? AND email = ? AND reset_token = ? AND used = FALSE AND expires_at > NOW()`,
      [decoded.resetId, decoded.email, resetToken],
    )

    if (resets.length === 0) {
      return res.status(400).json({ error: "Token inválido o ya utilizado." })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10)

    await pool.query("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, decoded.email])

    await pool.query("UPDATE password_resets SET used = TRUE, used_at = NOW() WHERE id = ?", [decoded.resetId])

    res.json({ message: "Contraseña actualizada exitosamente." })
  } catch (error) {
    console.error("Error resetting password:", error)
    res.status(500).json({ error: "Error al restablecer contraseña." })
  }
})

app.get("/api/admin/password-resets", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const [resets] = await pool.query(
      `SELECT id, email, code, used, created_at, expires_at, used_at, ip_address
       FROM password_resets
       ORDER BY created_at DESC
       LIMIT 50`,
    )

    res.json({ resets })
  } catch (error) {
    console.error("Error fetching reset tokens:", error)
    res.status(500).json({ error: "Error al obtener tokens de recuperación." })
  }
})

app.get("/api/dashboard/student", authenticateToken, authorizeRole("student", "admin"), async (req, res) => {
  try {
    const userId = req.user.role === "admin" ? req.query.userId || req.user.id : req.user.id

    const [enrollments] = await pool.query(
      `SELECT e.*, c.title, c.description, c.difficulty_level, c.duration_hours,
              u.first_name as instructor_first_name, u.last_name as instructor_last_name
       FROM enrollments e
       JOIN courses c ON e.course_id = c.id
       LEFT JOIN users u ON c.instructor_id = u.id
       WHERE e.user_id = ?
       ORDER BY e.enrollment_date DESC`,
      [userId],
    )

    res.json({ enrollments })
  } catch (error) {
    console.error("Error en dashboard estudiante:", error)
    res.status(500).json({ error: "Error al cargar dashboard." })
  }
})

app.get("/api/dashboard/instructor", authenticateToken, authorizeRole("instructor", "admin"), async (req, res) => {
  try {
    const userId = req.user.role === "admin" ? req.query.userId || req.user.id : req.user.id

    const [courses] = await pool.query(
      `SELECT c.*, COUNT(DISTINCT e.id) as enrolled_students
       FROM courses c
       LEFT JOIN enrollments e ON c.id = e.course_id
       WHERE c.instructor_id = ?
       GROUP BY c.id
       ORDER BY c.created_at DESC`,
      [userId],
    )

    res.json({ courses })
  } catch (error) {
    console.error("Error en dashboard instructor:", error)
    res.status(500).json({ error: "Error al cargar dashboard." })
  }
})

app.get("/api/dashboard/admin", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const [userStats] = await pool.query("SELECT role, COUNT(*) as count FROM users GROUP BY role")

    const [courseStats] = await pool.query(
      "SELECT COUNT(*) as total_courses, SUM(is_published) as published_courses FROM courses",
    )

    const [enrollmentStats] = await pool.query("SELECT COUNT(*) as total_enrollments FROM enrollments")

    const [recentUsers] = await pool.query(
      "SELECT id, employee_id, email, first_name, last_name, role, created_at FROM users ORDER BY created_at DESC LIMIT 10",
    )

    res.json({
      stats: {
        users: userStats,
        courses: courseStats[0],
        enrollments: enrollmentStats[0],
      },
      recentUsers,
    })
  } catch (error) {
    console.error("Error en dashboard admin:", error)
    res.status(500).json({ error: "Error al cargar dashboard." })
  }
})

app.get("/api/courses", async (req, res) => {
  try {
    const {
      q = "",
      category = "",
      level = "",
      instructor = "",
      min_duration = "",
      max_duration = "",
      sort = "created_at",
      order = "DESC",
      page = 1,
      limit = 12,
    } = req.query

    const offset = (Number.parseInt(page) - 1) * Number.parseInt(limit)

    let query = `
      SELECT c.*,
             u.first_name as instructor_first_name,
             u.last_name as instructor_last_name,
             u.email as instructor_email,
             COUNT(DISTINCT e.id) as enrolled_count,
             COUNT(DISTINCT l.id) as lessons_count
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      LEFT JOIN enrollments e ON c.id = e.course_id
      LEFT JOIN lessons l ON c.id = l.course_id
      WHERE c.published = TRUE
    `

    const params = []

    if (q) {
      query += ` AND (c.title LIKE ? OR c.description LIKE ?)`
      params.push(`%${q}%`, `%${q}%`)
    }

    if (category) {
      query += ` AND (c.category = ? OR c.categories LIKE ?)`
      params.push(category, `%${category}%`)
    }

    if (level) {
      query += ` AND c.level = ?`
      params.push(level)
    }

    if (instructor) {
      query += ` AND c.instructor_id = ?`
      params.push(instructor)
    }

    if (min_duration) {
      query += ` AND c.duration_minutes >= ?`
      params.push(Number.parseInt(min_duration))
    }

    if (max_duration) {
      query += ` AND c.duration_minutes <= ?`
      params.push(Number.parseInt(max_duration))
    }

    query += ` GROUP BY c.id`

    const validSortFields = ["created_at", "title", "duration_minutes", "level"]
    const validOrders = ["ASC", "DESC"]
    const sortField = validSortFields.includes(sort) ? sort : "created_at"
    const sortOrder = validOrders.includes(order.toUpperCase()) ? order.toUpperCase() : "DESC"

    query += ` ORDER BY c.${sortField} ${sortOrder}`

    query += ` LIMIT ? OFFSET ?`
    params.push(Number.parseInt(limit), offset)

    const [courses] = await pool.query(query, params)

    let countQuery = `
      SELECT COUNT(DISTINCT c.id) as total
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE c.published = TRUE
    `

    const countParams = []

    if (q) {
      countQuery += ` AND (c.title LIKE ? OR c.description LIKE ?)`
      countParams.push(`%${q}%`, `%${q}%`)
    }

    if (category) {
      countQuery += ` AND (c.category = ? OR c.categories LIKE ?)`
      countParams.push(category, `%${category}%`)
    }

    if (level) {
      countQuery += ` AND c.level = ?`
      countParams.push(level)
    }

    if (instructor) {
      countQuery += ` AND c.instructor_id = ?`
      countParams.push(instructor)
    }

    if (min_duration) {
      countQuery += ` AND c.duration_minutes >= ?`
      countParams.push(Number.parseInt(min_duration))
    }

    if (max_duration) {
      countQuery += ` AND c.duration_minutes <= ?`
      countParams.push(Number.parseInt(max_duration))
    }

    const [countResult] = await pool.query(countQuery, countParams)
    const total = countResult[0].total

    res.json({
      courses,
      pagination: {
        page: Number.parseInt(page),
        limit: Number.parseInt(limit),
        total,
        totalPages: Math.ceil(total / Number.parseInt(limit)),
      },
    })
  } catch (error) {
    console.error("Error fetching courses:", error)
    res.status(500).json({ error: "Error al obtener cursos." })
  }
})

app.get("/api/courses/:id", async (req, res) => {
  try {
    const { id } = req.params

    const [courses] = await pool.query(
      `SELECT c.*,
              u.first_name as instructor_first_name,
              u.last_name as instructor_last_name,
              u.email as instructor_email,
              u.position as instructor_position,
              COUNT(DISTINCT e.id) as enrolled_count
       FROM courses c
       LEFT JOIN users u ON c.instructor_id = u.id
       LEFT JOIN enrollments e ON c.id = e.course_id
       WHERE c.id = ? AND c.published = TRUE
       GROUP BY c.id`,
      [id],
    )

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    const [lessons] = await pool.query(
      `SELECT id, title, slug, description, order_index, duration_seconds, is_free_preview
       FROM lessons
       WHERE course_id = ?
       ORDER BY order_index ASC`,
      [id],
    )

    const course = { ...courses[0], lessons }

    res.json({ course })
  } catch (error) {
    console.error("Error fetching course:", error)
    res.status(500).json({ error: "Error al obtener curso." })
  }
})

app.get("/api/courses/:id/preview", async (req, res) => {
  try {
    const { id } = req.params

    const [courses] = await pool.query(
      `SELECT c.id, c.title, c.description, c.level, c.duration_minutes, c.thumbnail_url,
              u.first_name as instructor_first_name,
              u.last_name as instructor_last_name
       FROM courses c
       LEFT JOIN users u ON c.instructor_id = u.id
       WHERE c.id = ? AND c.published = TRUE`,
      [id],
    )

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    const [lessons] = await pool.query(
      `SELECT id, title, description, duration_seconds
       FROM lessons
       WHERE course_id = ? AND is_free_preview = TRUE
       ORDER BY order_index ASC`,
      [id],
    )

    res.json({ course: courses[0], previewLessons: lessons })
  } catch (error) {
    console.error("Error fetching course preview:", error)
    res.status(500).json({ error: "Error al obtener vista previa del curso." })
  }
})

app.post("/api/courses", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { title, slug, description, category, level, duration_minutes, thumbnail_url, price, published } = req.body

    if (!title || !description) {
      return res.status(400).json({ error: "Título y descripción son obligatorios." })
    }

    const instructorId = req.user.role === "admin" && req.body.instructor_id ? req.body.instructor_id : req.user.id

    const courseSlug = slug || title.toLowerCase().replace(/[^a-z0-9]+/g, "-")

    const [result] = await pool.query(
      `INSERT INTO courses
         (title, slug, description, instructor_id, category, level, duration_minutes,
          thumbnail_url, price, published, is_published)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        title,
        courseSlug,
        description,
        instructorId,
        category || "General",
        level || "beginner",
        duration_minutes || 0,
        thumbnail_url || "",
        price || 0.0,
        published || false,
        published || false,
      ],
    )

    res.status(201).json({
      message: "Curso creado exitosamente.",
      courseId: result.insertId,
    })
  } catch (error) {
    console.error("Error creating course:", error)
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Ya existe un curso con ese slug." })
    }
    res.status(500).json({ error: "Error al crear curso." })
  }
})

app.put("/api/courses/:id", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { id } = req.params
    const {
      title,
      slug,
      description,
      category,
      category_id,
      level,
      duration_approx,
      duration_minutes,
      thumbnail_url,
      video_url,
      price,
      published,
    } = req.body

    const [courses] = await pool.query("SELECT instructor_id FROM courses WHERE id = ?", [id])

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    if (req.user.role !== "admin" && courses[0].instructor_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para editar este curso." })
    }

    let dbLevel
    switch ((level || "").toLowerCase()) {
      case "principiante":
      case "beginner":
        dbLevel = "beginner"
        break
      case "intermedio":
      case "intermediate":
        dbLevel = "intermediate"
        break
      case "avanzado":
      case "advanced":
        dbLevel = "advanced"
        break
      default:
        dbLevel = null
    }

    const updates = []
    const values = []

    if (title !== undefined) {
      updates.push("title = ?")
      values.push(title)
    }
    if (slug !== undefined) {
      updates.push("slug = ?")
      values.push(slug)
    }
    if (description !== undefined) {
      updates.push("description = ?")
      values.push(description)
    }
    if (category !== undefined) {
      updates.push("category = ?")
      values.push(category)
    }
    if (category_id !== undefined) {
      updates.push("category_id = ?")
      values.push(category_id)
    }
    if (dbLevel !== null) {
      updates.push("level = ?")
      values.push(dbLevel)
    }
    if (duration_approx !== undefined) {
      updates.push("duration_approx = ?")
      values.push(duration_approx)
    }
    if (duration_minutes !== undefined) {
      updates.push("duration_minutes = ?")
      values.push(duration_minutes)
    }
    if (video_url !== undefined) {
      updates.push("video_url = ?")
      values.push(video_url)
    }
    if (thumbnail_url !== undefined) {
      updates.push("thumbnail_url = ?")
      values.push(thumbnail_url)
    }
    if (price !== undefined) {
      updates.push("price = ?")
      values.push(price)
    }
    if (published !== undefined) {
      updates.push("published = ?")
      updates.push("is_published = ?")
      values.push(published, published)
    }

    if (updates.length > 0) {
      values.push(id)
      await pool.query(`UPDATE courses SET ${updates.join(", ")} WHERE id = ?`, values)
    }

    res.json({ message: "Curso actualizado exitosamente." })
  } catch (error) {
    console.error("Error updating course:", error)
    res.status(500).json({ error: "Error al actualizar curso." })
  }
})

app.delete("/api/courses/:id", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { id } = req.params

    const [courses] = await pool.query("SELECT instructor_id FROM courses WHERE id = ?", [id])

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    if (req.user.role !== "admin" && courses[0].instructor_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para eliminar este curso." })
    }

    await pool.query("DELETE FROM courses WHERE id = ?", [id])

    res.json({ message: "Curso eliminado exitosamente." })
  } catch (error) {
    console.error("Error deleting course:", error)
    res.status(500).json({ error: "Error al eliminar curso." })
  }
})

app.get("/api/courses/meta/categories", async (req, res) => {
  try {
    const [categories] = await pool.query(
      `SELECT DISTINCT category FROM courses WHERE published = TRUE AND category IS NOT NULL ORDER BY category`,
    )

    res.json({ categories: categories.map((c) => c.category) })
  } catch (error) {
    console.error("Error fetching categories:", error)
    res.status(500).json({ error: "Error al obtener categorías." })
  }
})

app.get("/api/courses/meta/instructors", async (req, res) => {
  try {
    const [instructors] = await pool.query(
      `SELECT DISTINCT u.id, u.first_name, u.last_name
       FROM users u
       JOIN courses c ON u.id = c.instructor_id
       WHERE u.role IN ('instructor', 'admin') AND c.published = TRUE
       ORDER BY u.first_name`,
    )

    res.json({ instructors })
  } catch (error) {
    console.error("Error fetching instructors:", error)
    res.status(500).json({ error: "Error al obtener instructores." })
  }
})

app.post("/api/courses/create-with-quiz", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  const connection = await pool.getConnection()

  try {
    await connection.beginTransaction()

    const { title, description, level, duration_approx, video_url, published, category, questions } = req.body

    if (!title || !description || !questions || questions.length === 0) {
      await connection.rollback()
      return res.status(400).json({ error: "Título, descripción y al menos una pregunta son obligatorios." })
    }

    if (questions.length > 10) {
      await connection.rollback()
      return res.status(400).json({ error: "Máximo 10 preguntas permitidas." })
    }

    const instructorId = req.user.role === "admin" && req.body.instructor_id ? req.body.instructor_id : req.user.id
    const courseSlug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-")

    let duration_hours = 0
    let duration_minutes = 0

    if (duration_approx) {
      const num = Number.parseInt(duration_approx)

      if (duration_approx.includes("semana")) {
        duration_hours = num * 40
      } else if (duration_approx.includes("hora")) {
        duration_hours = num
      } else if (duration_approx.includes("minuto")) {
        duration_minutes = num
      }
    }

    const levelMap = {
      Principiante: "beginner",
      Intermedio: "intermediate",
      Avanzado: "advanced",
    }

    const mappedLevel = levelMap[level] || "beginner"

    const [courseResult] = await connection.query(
      `INSERT INTO courses
   (title, slug, description, instructor_id, category, level, duration_hours, duration_minutes,
    video_manifest, is_published, published, difficulty_level)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        title,
        courseSlug,
        description,
        instructorId,
        category || "General",
        mappedLevel,
        duration_hours,
        duration_minutes,
        video_url,
        true,
        true,
        mappedLevel,
      ],
    )

    const courseId = courseResult.insertId

    const [quizResult] = await connection.query(
      `INSERT INTO quizzes
       (course_id, title, description, passing_score, max_attempts, shuffle_questions, shuffle_answers)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [courseId, `Quiz: ${title}`, "Evaluación del curso", 70.0, 999, true, true],
    )

    const quizId = quizResult.insertId

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i]

      const [questionResult] = await connection.query(
        `INSERT INTO questions (quiz_id, question_text, question_type, points, order_index)
         VALUES (?, ?, ?, ?, ?)`,
        [quizId, q.text, q.type, 1.0, i + 1],
      )

      const questionId = questionResult.insertId

      if (q.type === "multiple_choice") {
        await connection.query(
          `INSERT INTO choices (question_id, choice_text, is_correct, order_index)
           VALUES (?, ?, ?, ?)`,
          [questionId, q.options.correct, true, 1],
        )

        const wrongAnswers = [q.options.wrong1, q.options.wrong2, q.options.wrong3]
        for (let j = 0; j < wrongAnswers.length; j++) {
          await connection.query(
            `INSERT INTO choices (question_id, choice_text, is_correct, order_index)
             VALUES (?, ?, ?, ?)`,
            [questionId, wrongAnswers[j], false, j + 2],
          )
        }
      } else if (q.type === "true_false") {
        await connection.query(
          `INSERT INTO choices (question_id, choice_text, is_correct, order_index)
           VALUES (?, ?, ?, ?), (?, ?, ?, ?)`,
          [
            questionId,
            "Verdadero",
            q.options.answer === "true",
            1,
            questionId,
            "Falso",
            q.options.answer === "false",
            2,
          ],
        )
      } else if (q.type === "matching") {
        for (let j = 0; j < q.options.pairs.length; j++) {
          const pair = q.options.pairs[j]
          await connection.query(
            `INSERT INTO matching_pairs (question_id, statement, correct_match, order_index)
             VALUES (?, ?, ?, ?)`,
            [questionId, pair.statement, pair.match, j + 1],
          )
        }
      }
    }

    await connection.commit()

    res.status(201).json({
      message: "Curso y quiz creados exitosamente.",
      courseId,
      quizId,
    })
  } catch (error) {
    await connection.rollback()
    console.error("Error creating course with quiz:", error)
    res.status(500).json({ error: "Error al crear curso." })
  } finally {
    connection.release()
  }
})

app.get(
  "/api/courses/:id/full",
  authenticateToken,
  authorizeRole("student", "admin", "instructor"),
  async (req, res) => {
    try {
      const { id } = req.params

      const [courses] = await pool.query(`SELECT * FROM courses WHERE id = ?`, [id])

      if (courses.length === 0) {
        return res.status(404).json({ error: "Curso no encontrado." })
      }

      const course = courses[0]

      if (req.user.role === "instructor" && course.instructor_id !== req.user.id) {
        return res.status(403).json({ error: "No tienes permisos para ver este curso." })
      }

      const [quizzes] = await pool.query(`SELECT * FROM quizzes WHERE course_id = ? LIMIT 1`, [id])

      if (quizzes.length > 0) {
        const [questions] = await pool.query(`SELECT * FROM questions WHERE quiz_id = ? ORDER BY order_index`, [
          quizzes[0].id,
        ])

        course.quiz = quizzes[0]
        course.questions = questions
      }

      res.json({ course })
    } catch (error) {
      console.error("Error fetching full course:", error)
      res.status(500).json({ error: "Error al obtener curso." })
    }
  },
)

app.post("/api/courses/assign", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { course_id, student_id } = req.body

    if (!course_id || !student_id) {
      return res.status(400).json({ error: "course_id y student_id son obligatorios." })
    }

    if (req.user.role === "instructor") {
      const [courses] = await pool.query("SELECT instructor_id FROM courses WHERE id = ?", [course_id])

      if (courses.length === 0) {
        return res.status(404).json({ error: "Curso no encontrado." })
      }

      if (courses[0].instructor_id !== req.user.id) {
        return res.status(403).json({ error: "No tienes permisos para asignar este curso." })
      }
    }

    const [students] = await pool.query("SELECT id, role FROM users WHERE id = ? AND role = 'student'", [student_id])

    if (students.length === 0) {
      return res.status(404).json({ error: "Estudiante no encontrado." })
    }

    await pool.query(
      `INSERT INTO course_assignments (course_id, student_id, assigned_by)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE assigned_at = CURRENT_TIMESTAMP`,
      [course_id, student_id, req.user.id],
    )

    await pool.query(
      `INSERT INTO enrollments (user_id, course_id, enrollment_type, status)
       VALUES (?, ?, 'assigned', 'enrolled')
       ON DUPLICATE KEY UPDATE enrollment_type = 'assigned'`,
      [student_id, course_id],
    )

    await pool.query(
      `INSERT INTO student_courses (student_id, course_id, progress, passed)
       VALUES (?, ?, 0, FALSE)
       ON DUPLICATE KEY UPDATE enrolled_at = CURRENT_TIMESTAMP`,
      [student_id, course_id],
    )

    res.json({ message: "Curso asignado exitosamente." })
  } catch (error) {
    console.error("Error assigning course:", error)
    res.status(500).json({ error: "Error al asignar curso." })
  }
})

app.get("/api/users/students", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const [students] = await pool.query(
      `SELECT id, email, first_name, last_name, employee_id
       FROM users
       WHERE role = 'student' AND is_active = TRUE
       ORDER BY first_name, last_name`,
    )

    res.json({ students })
  } catch (error) {
    console.error("Error fetching students:", error)
    res.status(500).json({ error: "Error al obtener estudiantes." })
  }
})

app.put("/api/courses/:id", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { id } = req.params
    const {
      title,
      slug,
      description,
      category,
      category_id,
      level,
      duration_minutes,
      duration_approx,
      thumbnail_url,
      price,
      published,
      video_url,
    } = req.body

    const [courses] = await pool.query("SELECT instructor_id FROM courses WHERE id = ?", [id])

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    if (req.user.role !== "admin" && courses[0].instructor_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para editar este curso." })
    }

    await pool.query(
      `UPDATE courses
       SET title = COALESCE(?, title),
           slug = COALESCE(?, slug),
           description = COALESCE(?, description),
           category = COALESCE(?, category),
           category_id = COALESCE(?, category_id),
           level = COALESCE(?, level),
           difficulty_level = COALESCE(?, difficulty_level),
           duration_minutes = COALESCE(?, duration_minutes),
           duration_approx = COALESCE(?, duration_approx),
           thumbnail_url = COALESCE(?, thumbnail_url),
           price = COALESCE(?, price),
           published = COALESCE(?, published),
           is_published = COALESCE(?, is_published),
           video_url = COALESCE(?, video_url),
           video_manifest = COALESCE(?, video_manifest),
           updated_at = NOW()
       WHERE id = ?`,
      [
        title,
        slug,
        description,
        category,
        category_id,
        level,
        level,
        duration_minutes,
        duration_approx,
        thumbnail_url,
        price,
        published,
        published,
        video_url,
        video_url,
        id,
      ],
    )

    res.json({ message: "Curso actualizado exitosamente." })
  } catch (error) {
    console.error("Error updating course:", error)
    res.status(500).json({ error: "Error al actualizar curso." })
  }
})

app.get("/api/enrollments", authenticateToken, async (req, res) => {
  try {
    const [enrollments] = await pool.query(
      `SELECT e.*, c.title as course_title
       FROM enrollments e
       JOIN courses c ON e.course_id = c.id
       WHERE e.user_id = ?
       ORDER BY e.enrollment_date DESC`,
      [req.user.id],
    )

    res.json({ enrollments })
  } catch (error) {
    console.error("Error fetching enrollments:", error)
    res.status(500).json({ error: "Error al obtener inscripciones." })
  }
})

app.post("/api/enrollments", authenticateToken, async (req, res) => {
  try {
    const { course_id } = req.body

    if (!course_id) {
      return res.status(400).json({ error: "course_id es obligatorio." })
    }

    const [courses] = await pool.query("SELECT id FROM courses WHERE id = ? AND published = TRUE", [course_id])

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    const [existingEnrollment] = await pool.query("SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?", [
      req.user.id,
      course_id,
    ])

    if (existingEnrollment.length > 0) {
      return res.status(409).json({ error: "Ya estás inscrito en este curso." })
    }

    const [result] = await pool.query(
      `INSERT INTO enrollments (user_id, course_id, status)
       VALUES (?, ?, 'enrolled')`,
      [req.user.id, course_id],
    )

    res.status(201).json({
      message: "Inscripción exitosa.",
      enrollmentId: result.insertId,
    })
  } catch (error) {
    console.error("Error creating enrollment:", error)
    res.status(500).json({ error: "Error al crear inscripción." })
  }
})

app.get("/api/lessons/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params

    const [lessons] = await pool.query(
      `SELECT l.*, c.title as course_title, c.instructor_id
       FROM lessons l
       JOIN courses c ON l.course_id = c.id
       WHERE l.id = ?`,
      [id],
    )

    if (lessons.length === 0) {
      return res.status(404).json({ error: "Lección no encontrada." })
    }

    const lesson = lessons[0]

    const [enrollment] = await pool.query("SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?", [
      req.user.id,
      lesson.course_id,
    ])

    if (enrollment.length === 0 && req.user.role !== "admin" && lesson.instructor_id !== req.user.id) {
      if (!lesson.is_free_preview) {
        return res.status(403).json({ error: "Debes inscribirte en el curso para acceder a esta lección." })
      }
    }

    res.json({ lesson })
  } catch (error) {
    console.error("Error fetching lesson:", error)
    res.status(500).json({ error: "Error al obtener lección." })
  }
})

app.post("/api/lessons", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { course_id, title, slug, description, content, order_index, duration_seconds, video_url, is_free_preview } =
      req.body

    if (!course_id || !title) {
      return res.status(400).json({ error: "course_id y title son obligatorios." })
    }

    if (req.user.role === "instructor") {
      const [courses] = await pool.query("SELECT instructor_id FROM courses WHERE id = ?", [course_id])

      if (courses.length === 0 || courses[0].instructor_id !== req.user.id) {
        return res.status(403).json({ error: "No tienes permisos para agregar lecciones a este curso." })
      }
    }

    const lessonSlug = slug || title.toLowerCase().replace(/[^a-z0-9]+/g, "-")

    const [result] = await pool.query(
      `INSERT INTO lessons
       (course_id, title, slug, description, content, order_index, duration_seconds, video_url, is_free_preview)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        course_id,
        title,
        lessonSlug,
        description || "",
        content || "",
        order_index || 1,
        duration_seconds || 0,
        video_url || "",
        is_free_preview || false,
      ],
    )

    res.status(201).json({
      message: "Lección creada exitosamente.",
      lessonId: result.insertId,
    })
  } catch (error) {
    console.error("Error creating lesson:", error)
    res.status(500).json({ error: "Error al crear lección." })
  }
})

app.put("/api/lessons/:id", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { id } = req.params
    const { title, slug, description, content, order_index, duration_seconds, video_url, is_free_preview } = req.body

    const [lessons] = await pool.query(
      "SELECT l.*, c.instructor_id FROM lessons l JOIN courses c ON l.course_id = c.id WHERE l.id = ?",
      [id],
    )

    if (lessons.length === 0) {
      return res.status(404).json({ error: "Lección no encontrada." })
    }

    if (req.user.role === "instructor" && lessons[0].instructor_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para editar esta lección." })
    }

    const updates = []
    const values = []

    if (title !== undefined) {
      updates.push("title = ?")
      values.push(title)
    }
    if (slug !== undefined) {
      updates.push("slug = ?")
      values.push(slug)
    }
    if (description !== undefined) {
      updates.push("description = ?")
      values.push(description)
    }
    if (content !== undefined) {
      updates.push("content = ?")
      values.push(content)
    }
    if (order_index !== undefined) {
      updates.push("order_index = ?")
      values.push(order_index)
    }
    if (duration_seconds !== undefined) {
      updates.push("duration_seconds = ?")
      values.push(duration_seconds)
    }
    if (video_url !== undefined) {
      updates.push("video_url = ?")
      values.push(video_url)
    }
    if (is_free_preview !== undefined) {
      updates.push("is_free_preview = ?")
      values.push(is_free_preview)
    }

    if (updates.length > 0) {
      values.push(id)
      await pool.query(`UPDATE lessons SET ${updates.join(", ")} WHERE id = ?`, values)
    }

    res.json({ message: "Lección actualizada exitosamente." })
  } catch (error) {
    console.error("Error updating lesson:", error)
    res.status(500).json({ error: "Error al actualizar lección." })
  }
})

app.delete("/api/lessons/:id", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const { id } = req.params

    const [lessons] = await pool.query(
      "SELECT l.*, c.instructor_id FROM lessons l JOIN courses c ON l.course_id = c.id WHERE l.id = ?",
      [id],
    )

    if (lessons.length === 0) {
      return res.status(404).json({ error: "Lección no encontrada." })
    }

    if (req.user.role === "instructor" && lessons[0].instructor_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para eliminar esta lección." })
    }

    await pool.query("DELETE FROM lessons WHERE id = ?", [id])

    res.json({ message: "Lección eliminada exitosamente." })
  } catch (error) {
    console.error("Error deleting lesson:", error)
    res.status(500).json({ error: "Error al eliminar lección." })
  }
})

app.post("/api/lessons/:id/progress", authenticateToken, async (req, res) => {
  try {
    const { id: lesson_id } = req.params
    const { played_seconds, duration_seconds, event_type, course_id } = req.body

    if (!lesson_id || played_seconds === undefined) {
      return res.status(400).json({ error: "lesson_id y played_seconds son obligatorios." })
    }

    const progressPercentage = duration_seconds && duration_seconds > 0 ? (played_seconds / duration_seconds) * 100 : 0

    const completed = progressPercentage >= 90 || event_type === "ended"

    const [existing] = await pool.query("SELECT id FROM lesson_progress WHERE user_id = ? AND lesson_id = ?", [
      req.user.id,
      lesson_id,
    ])

    if (existing.length > 0) {
      await pool.query(
        `UPDATE lesson_progress
         SET played_seconds = ?,
             duration_seconds = ?,
             progress_percentage = ?,
             completed = ?,
             last_position = ?,
             completed_at = CASE WHEN ? AND completed_at IS NULL THEN NOW() ELSE completed_at END,
             updated_at = NOW()
         WHERE id = ?`,
        [
          played_seconds,
          duration_seconds || 0,
          progressPercentage,
          completed,
          played_seconds,
          completed,
          existing[0].id,
        ],
      )
    } else {
      await pool.query(
        `INSERT INTO lesson_progress
         (user_id, lesson_id, course_id, played_seconds, duration_seconds, progress_percentage, completed, last_position, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.id,
          lesson_id,
          course_id,
          played_seconds,
          duration_seconds || 0,
          progressPercentage,
          completed,
          played_seconds,
          completed ? new Date() : null,
        ],
      )
    }

    await updateCourseProgress(req.user.id, course_id)

    res.json({
      message: "Progreso guardado exitosamente.",
      completed,
      progress_percentage: progressPercentage,
    })
  } catch (error) {
    console.error("Error saving progress:", error)
    res.status(500).json({ error: "Error al guardar progreso." })
  }
})

app.get("/api/courses/:courseId/progress", authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params
    const userId = req.query.userId || req.user.id

    if (req.user.role !== "admin" && userId != req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para ver este progreso." })
    }

    const [lessonsProgress] = await pool.query(
      `SELECT lp.*, l.title as lesson_title, l.order_index
       FROM lesson_progress lp
       JOIN lessons l ON lp.lesson_id = l.id
       WHERE lp.user_id = ? AND lp.course_id = ?
       ORDER BY l.order_index`,
      [userId, courseId],
    )

    const [courseProgress] = await pool.query(
      `SELECT progress_percentage, status, completion_date
       FROM enrollments
       WHERE user_id = ? AND course_id = ?`,
      [userId, courseId],
    )

    res.json({
      lessons: lessonsProgress,
      course: courseProgress[0] || null,
    })
  } catch (error) {
    console.error("Error fetching progress:", error)
    res.status(500).json({ error: "Error al obtener progreso." })
  }
})

async function updateCourseProgress(userId, courseId) {
  try {
    const [stats] = await pool.query(
      `SELECT
         COUNT(l.id) as total_lessons,
         COUNT(CASE WHEN lp.completed = TRUE THEN 1 END) as completed_lessons
       FROM lessons l
       LEFT JOIN lesson_progress lp ON l.id = lp.lesson_id AND lp.user_id = ?
       WHERE l.course_id = ?`,
      [userId, courseId],
    )

    if (stats[0].total_lessons > 0) {
      const progressPercentage = (stats[0].completed_lessons / stats[0].total_lessons) * 100
      const status = progressPercentage >= 100 ? "completed" : progressPercentage > 0 ? "in_progress" : "enrolled"

      await pool.query(
        `UPDATE enrollments
         SET progress_percentage = ?,
             status = ?,
             completion_date = CASE WHEN ? = 'completed' AND completion_date IS NULL THEN NOW() ELSE completion_date END
         WHERE user_id = ? AND course_id = ?`,
        [progressPercentage, status, status, userId, courseId],
      )
    }
  } catch (error) {
    console.error("Error updating course progress:", error)
  }
}

app.get("/api/quizzes/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params

    const [quizzes] = await pool.query(
      `SELECT q.*, c.title as course_title
       FROM quizzes q
       JOIN courses c ON q.course_id = c.id
       WHERE q.id = ? AND q.is_active = TRUE`,
      [id],
    )

    if (quizzes.length === 0) {
      return res.status(404).json({ error: "Evaluación no encontrada." })
    }

    const [questions] = await pool.query(
      `SELECT id, question_text, question_type, points, order_index
       FROM questions
       WHERE quiz_id = ?
       ORDER BY order_index`,
      [id],
    )

    for (const question of questions) {
      const [choices] = await pool.query(
        `SELECT id, choice_text, order_index
         FROM choices
         WHERE question_id = ?
         ORDER BY order_index`,
        [question.id],
      )
      question.choices = choices
    }

    const quiz = quizzes[0]
    if (quiz.shuffle_questions) {
      questions.sort(() => Math.random() - 0.5)
    }

    if (quiz.shuffle_answers) {
      questions.forEach((q) => {
        if (q.choices) {
          q.choices.sort(() => Math.random() - 0.5)
        }
      })
    }

    res.json({ quiz, questions })
  } catch (error) {
    console.error("Error fetching quiz:", error)
    res.status(500).json({ error: "Error al obtener evaluación." })
  }
})

app.post("/api/quizzes", authenticateToken, authorizeRole("admin", "instructor"), async (req, res) => {
  try {
    const {
      course_id,
      lesson_id,
      title,
      description,
      time_limit_minutes,
      passing_score,
      max_attempts,
      shuffle_questions,
      shuffle_answers,
      show_correct_answers,
    } = req.body

    if (!course_id || !title) {
      return res.status(400).json({ error: "course_id y title son obligatorios." })
    }

    if (req.user.role === "instructor") {
      const [courses] = await pool.query("SELECT instructor_id FROM courses WHERE id = ?", [course_id])

      if (courses.length === 0 || courses[0].instructor_id !== req.user.id) {
        return res.status(403).json({ error: "No tienes permisos para crear evaluaciones en este curso." })
      }
    }

    const [result] = await pool.query(
      `INSERT INTO quizzes
       (course_id, lesson_id, title, description, time_limit_minutes, passing_score,
        max_attempts, shuffle_questions, shuffle_answers, show_correct_answers)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        course_id,
        lesson_id || null,
        title,
        description || "",
        time_limit_minutes || 30,
        passing_score || 70.0,
        max_attempts || 3,
        shuffle_questions !== false,
        shuffle_answers !== false,
        show_correct_answers !== false,
      ],
    )

    res.status(201).json({
      message: "Evaluación creada exitosamente.",
      quizId: result.insertId,
    })
  } catch (error) {
    console.error("Error creating quiz:", error)
    res.status(500).json({ error: "Error al crear evaluación." })
  }
})

app.post(
  "/api/quizzes/:quizId/questions",
  authenticateToken,
  authorizeRole("admin", "instructor"),
  async (req, res) => {
    try {
      const { quizId } = req.params
      const { question_text, question_type, points, explanation, choices } = req.body

      if (!question_text || !question_type) {
        return res.status(400).json({ error: "question_text y question_type son obligatorios." })
      }

      const [orderResult] = await pool.query(
        "SELECT COALESCE(MAX(order_index), 0) + 1 as next_order FROM questions WHERE quiz_id = ?",
        [quizId],
      )

      const [result] = await pool.query(
        `INSERT INTO questions (quiz_id, question_text, question_type, points, order_index, explanation)
       VALUES (?, ?, ?, ?, ?, ?)`,
        [quizId, question_text, question_type, points || 1.0, orderResult[0].next_order, explanation || ""],
      )

      const questionId = result.insertId

      if (choices && Array.isArray(choices) && choices.length > 0) {
        for (let i = 0; i < choices.length; i++) {
          await pool.query(
            `INSERT INTO choices (question_id, choice_text, is_correct, order_index)
           VALUES (?, ?, ?, ?)`,
            [questionId, choices[i].choice_text, choices[i].is_correct || false, i + 1],
          )
        }
      }

      res.status(201).json({
        message: "Pregunta agregada exitosamente.",
        questionId,
      })
    } catch (error) {
      console.error("Error adding question:", error)
      res.status(500).json({ error: "Error al agregar pregunta." })
    }
  },
)

app.post("/api/quizzes/:id/attempt", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params

    const [quizzes] = await pool.query("SELECT * FROM quizzes WHERE id = ? AND is_active = TRUE", [id])

    if (quizzes.length === 0) {
      return res.status(404).json({ error: "Evaluación no encontrada." })
    }

    const quiz = quizzes[0]

    const [attempts] = await pool.query(
      "SELECT COUNT(*) as attempt_count FROM quiz_attempts WHERE user_id = ? AND quiz_id = ?",
      [req.user.id, id],
    )

    if (attempts[0].attempt_count >= quiz.max_attempts) {
      return res.status(403).json({
        error: `Has alcanzado el número máximo de intentos (${quiz.max_attempts}).`,
      })
    }

    const attemptNumber = attempts[0].attempt_count + 1

    const [questionsResult] = await pool.query("SELECT SUM(points) as total_points FROM questions WHERE quiz_id = ?", [
      id,
    ])

    const maxScore = questionsResult[0].total_points || 100.0

    const [result] = await pool.query(
      `INSERT INTO quiz_attempts (user_id, quiz_id, attempt_number, max_score)
       VALUES (?, ?, ?, ?)`,
      [req.user.id, id, attemptNumber, maxScore],
    )

    res.status(201).json({
      message: "Intento iniciado exitosamente.",
      attemptId: result.insertId,
      attemptNumber,
      timeLimit: quiz.time_limit_minutes,
    })
  } catch (error) {
    console.error("Error starting attempt:", error)
    res.status(500).json({ error: "Error al iniciar intento." })
  }
})

app.post("/api/quizzes/:id/attempt/:attemptId/answer", authenticateToken, async (req, res) => {
  try {
    const { attemptId } = req.params
    const { question_id, choice_id, answer_text, selected_choices } = req.body

    if (!question_id) {
      return res.status(400).json({ error: "question_id es obligatorio." })
    }

    const [attempts] = await pool.query("SELECT * FROM quiz_attempts WHERE id = ? AND user_id = ?", [
      attemptId,
      req.user.id,
    ])

    if (attempts.length === 0) {
      return res.status(404).json({ error: "Intento no encontrado." })
    }

    if (attempts[0].submitted) {
      return res.status(403).json({ error: "Este intento ya fue enviado." })
    }

    const [questions] = await pool.query("SELECT * FROM questions WHERE id = ?", [question_id])

    if (questions.length === 0) {
      return res.status(404).json({ error: "Pregunta no encontrada." })
    }

    const question = questions[0]
    let isCorrect = false
    let pointsEarned = 0

    if (question.question_type === "multiple_choice") {
      const [choices] = await pool.query("SELECT is_correct FROM choices WHERE id = ?", [choice_id])

      if (choices.length > 0 && choices[0].is_correct) {
        isCorrect = true
        pointsEarned = question.points
      }
    } else if (question.question_type === "true_false") {
      const [choices] = await pool.query("SELECT is_correct FROM choices WHERE id = ?", [choice_id])

      if (choices.length > 0 && choices[0].is_correct) {
        isCorrect = true
        pointsEarned = question.points
      }
    } else if (question.question_type === "multiple_select") {
      const [correctChoices] = await pool.query("SELECT id FROM choices WHERE question_id = ? AND is_correct = TRUE", [
        question_id,
      ])

      const correctIds = correctChoices.map((c) => c.id)
      const selectedIds = JSON.parse(selected_choices || "[]")

      if (correctIds.length === selectedIds.length && correctIds.every((id) => selectedIds.includes(id))) {
        isCorrect = true
        pointsEarned = question.points
      }
    }

    await pool.query(
      `INSERT INTO answers (attempt_id, question_id, choice_id, answer_text, selected_choices, is_correct, points_earned)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         choice_id = VALUES(choice_id),
         answer_text = VALUES(answer_text),
         selected_choices = VALUES(selected_choices),
         is_correct = VALUES(is_correct),
         points_earned = VALUES(points_earned)`,
      [
        attemptId,
        question_id,
        choice_id || null,
        answer_text || null,
        selected_choices || null,
        isCorrect,
        pointsEarned,
      ],
    )

    res.json({
      message: "Respuesta guardada exitosamente.",
      isCorrect,
      pointsEarned,
    })
  } catch (error) {
    console.error("Error saving answer:", error)
    res.status(500).json({ error: "Error al guardar respuesta." })
  }
})

app.post("/api/quizzes/:id/attempt/:attemptId/submit", authenticateToken, async (req, res) => {
  try {
    const { attemptId } = req.params

    const [attempts] = await pool.query("SELECT * FROM quiz_attempts WHERE id = ? AND user_id = ?", [
      attemptId,
      req.user.id,
    ])

    if (attempts.length === 0) {
      return res.status(404).json({ error: "Intento no encontrado." })
    }

    if (attempts[0].submitted) {
      return res.status(403).json({ error: "Este intento ya fue enviado." })
    }

    const attempt = attempts[0]

    const [scoreResult] = await pool.query(
      "SELECT SUM(points_earned) as total_score FROM answers WHERE attempt_id = ?",
      [attemptId],
    )

    const totalScore = scoreResult[0].total_score || 0
    const scorePercentage = attempt.max_score > 0 ? (totalScore / attempt.max_score) * 100 : 0

    const [quizzes] = await pool.query("SELECT passing_score FROM quizzes WHERE id = ?", [attempt.quiz_id])
    const passingScore = quizzes[0].passing_score || 70.0

    const passed = scorePercentage >= passingScore

    const timeSpent = Math.floor((Date.now() - new Date(attempt.started_at).getTime()) / 1000)

    await pool.query(
      `UPDATE quiz_attempts
       SET score = ?, passed = ?, time_spent_seconds = ?, completed_at = NOW(), submitted = TRUE
       WHERE id = ?`,
      [scorePercentage, passed, timeSpent, attemptId],
    )

    res.json({
      message: "Evaluación enviada exitosamente.",
      score: scorePercentage,
      passed,
      totalScore,
      maxScore: attempt.max_score,
    })
  } catch (error) {
    console.error("Error submitting attempt:", error)
    res.status(500).json({ error: "Error al enviar evaluación." })
  }
})

app.get("/api/quizzes/:id/attempt/:attemptId/results", authenticateToken, async (req, res) => {
  try {
    const { attemptId } = req.params

    const [attempts] = await pool.query(
      "SELECT qa.*, q.show_correct_answers FROM quiz_attempts qa JOIN quizzes q ON qa.quiz_id = q.id WHERE qa.id = ?",
      [attemptId],
    )

    if (attempts.length === 0) {
      return res.status(404).json({ error: "Intento no encontrado." })
    }

    if (req.user.role !== "admin" && attempts[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "No tienes permisos para ver estos resultados." })
    }

    const attempt = attempts[0]

    const [answers] = await pool.query(
      `SELECT a.*, q.question_text, q.question_type, q.explanation, q.points as question_points
       FROM answers a
       JOIN questions q ON a.question_id = q.id
       WHERE a.attempt_id = ?
       ORDER BY q.order_index`,
      [attemptId],
    )

    if (attempt.show_correct_answers) {
      for (const answer of answers) {
        const [choices] = await pool.query(
          `SELECT id, choice_text, is_correct FROM choices WHERE question_id = ? ORDER BY order_index`,
          [answer.question_id],
        )
        answer.choices = choices
      }
    }

    res.json({
      attempt,
      answers,
    })
  } catch (error) {
    console.error("Error fetching results:", error)
    res.status(500).json({ error: "Error al obtener resultados." })
  }
})

app.get("/api/quizzes/:id/attempts", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params

    const [attempts] = await pool.query(
      `SELECT * FROM quiz_attempts WHERE user_id = ? AND quiz_id = ? ORDER BY started_at DESC`,
      [req.user.id, id],
    )

    res.json({ attempts })
  } catch (error) {
    console.error("Error fetching attempts:", error)
    res.status(500).json({ error: "Error al obtener intentos." })
  }
})

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"))
})

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"))
})

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"))
})

app.get("/forgot-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "forgot-password.html"))
})

app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset-password.html"))
})

app.get("/dashboard/student", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard-student.html"))
})

app.get("/dashboard/instructor", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard-instructor.html"))
})

app.get("/dashboard/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard-admin.html"))
})

app.get("/courses", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "courses.html"))
})

app.get("/courses/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "course-detail.html"))
})

app.get("/lessons/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "lesson.html"))
})

app.get("/quizzes/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "quiz.html"))
})

app.get("/quizzes/:id/results/:attemptId", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "quiz-results.html"))
})

app.get("/api/quiz/:quizId/by-course", authenticateToken, async (req, res) => {
  try {
    const { quizId } = req.params

    const [quizzes] = await pool.query(`SELECT * FROM quizzes WHERE course_id = ? LIMIT 1`, [quizId])

    if (quizzes.length === 0) {
      return res.status(404).json({ error: "Quiz no encontrado para este curso." })
    }

    res.json({ quiz: quizzes[0] })
  } catch (error) {
    console.error("Error fetching quiz by course:", error)
    res.status(500).json({ error: "Error al obtener quiz." })
  }
})

app.get("/api/questions/:id/matching-pairs", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params

    const [pairs] = await pool.query(
      `SELECT id, statement, correct_match, order_index
       FROM matching_pairs
       WHERE question_id = ?
       ORDER BY order_index`,
      [id],
    )

    res.json({ pairs })
  } catch (error) {
    console.error("Error fetching matching pairs:", error)
    res.status(500).json({ error: "Error al obtener pares de emparejamiento." })
  }
})

app.post("/api/enroll", authenticateToken, authorizeRole("student"), async (req, res) => {
  try {
    const { courseId } = req.body

    if (!courseId) {
      return res.status(400).json({ error: "courseId es obligatorio." })
    }

    const [courses] = await pool.query("SELECT id FROM courses WHERE id = ? AND published = TRUE", [courseId])

    if (courses.length === 0) {
      return res.status(404).json({ error: "Curso no encontrado." })
    }

    const [existing] = await pool.query("SELECT id FROM student_courses WHERE student_id = ? AND course_id = ?", [
      req.user.id,
      courseId,
    ])

    if (existing.length > 0) {
      return res.status(409).json({ error: "Ya estás inscrito en este curso." })
    }

    const [result] = await pool.query(
      `INSERT INTO student_courses (student_id, course_id, enrolled_at, progress)
       VALUES (?, ?, NOW(), 0)`,
      [req.user.id, courseId],
    )

    res.status(201).json({
      message: "Te has inscrito al curso exitosamente.",
      enrollmentId: result.insertId,
    })
  } catch (error) {
    console.error("Error in /api/enroll:", error)
    res.status(500).json({ error: "Error al inscribirse al curso." })
  }
})

app.get("/api/student/courses", authenticateToken, authorizeRole("student", "admin"), async (req, res) => {
  try {
    const studentId = req.user.id

    const [assigned] = await pool.query(
      `SELECT sc.id, sc.student_id, sc.course_id, sc.enrolled_at, sc.progress, sc.score, sc.passed, sc.completed_at,
              c.id as course_id, c.title, c.description, c.level, c.duration_minutes, c.category,
              u.first_name as instructor_first_name, u.last_name as instructor_last_name
       FROM student_courses sc
       JOIN courses c ON sc.course_id = c.id
       LEFT JOIN users u ON c.instructor_id = u.id
       WHERE sc.student_id = ? AND (sc.passed = FALSE OR sc.passed IS NULL)
       ORDER BY sc.enrolled_at DESC`,
      [studentId],
    )

    const [finished] = await pool.query(
      `SELECT sc.id, sc.student_id, sc.course_id, sc.enrolled_at, sc.progress, sc.score, sc.passed, sc.completed_at,
              c.id as course_id, c.title, c.description, c.level, c.duration_minutes, c.category,
              u.first_name as instructor_first_name, u.last_name as instructor_last_name
       FROM student_courses sc
       JOIN courses c ON sc.course_id = c.id
       LEFT JOIN users u ON c.instructor_id = u.id
       WHERE sc.student_id = ? AND sc.passed = TRUE
       ORDER BY sc.completed_at DESC`,
      [studentId],
    )

    const [available] = await pool.query(
      `SELECT c.id, c.title, c.description, c.level, c.duration_minutes, c.category,
              u.first_name as instructor_first_name, u.last_name as instructor_last_name
       FROM courses c
       LEFT JOIN users u ON c.instructor_id = u.id
       WHERE c.published = TRUE AND c.id NOT IN (
         SELECT course_id FROM student_courses WHERE student_id = ?
       )
       ORDER BY c.created_at DESC`,
      [studentId],
    )

    res.json({
      assigned,
      finished,
      available,
    })
  } catch (error) {
    console.error("Error in /api/student/courses:", error)
    res.status(500).json({ error: "Error al obtener cursos." })
  }
})

app.put("/api/student/course/:courseId", authenticateToken, authorizeRole("student", "admin"), async (req, res) => {
  try {
    const { courseId } = req.params
    const { score, passed } = req.body

    const studentId = req.user.id

    const [enrollment] = await pool.query("SELECT id FROM student_courses WHERE student_id = ? AND course_id = ?", [
      studentId,
      courseId,
    ])

    if (enrollment.length === 0) {
      return res.status(404).json({ error: "No estás inscrito en este curso." })
    }

    await pool.query(
      `UPDATE student_courses
       SET score = ?, passed = ?, completed_at = ?, progress = 100
       WHERE student_id = ? AND course_id = ?`,
      [score || null, passed || false, passed ? new Date() : null, studentId, courseId],
    )

    res.json({ message: "Curso actualizado exitosamente.", passed, score })
  } catch (error) {
    console.error("Error updating course status:", error)
    res.status(500).json({ error: "Error al actualizar estado del curso." })
  }
})

app.get("/api/admin/categories", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const [categories] = await pool.query(
      `SELECT c.id, c.name, COUNT(co.id) as course_count
       FROM categories c
       LEFT JOIN courses co ON c.id = co.category_id
       GROUP BY c.id, c.name
       ORDER BY c.name`,
    )

    res.json({ categories })
  } catch (error) {
    console.error("Error in /api/admin/categories:", error)
    res.status(500).json({ error: "Error al obtener categorías." })
  }
})

app.post("/api/admin/categories", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const { name } = req.body

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: "El nombre de la categoría es obligatorio." })
    }

    const [result] = await pool.query("INSERT INTO categories (name) VALUES (?)", [name.trim()])

    res.status(201).json({
      message: "Categoría creada exitosamente.",
      categoryId: result.insertId,
      name: name.trim(),
    })
  } catch (error) {
    console.error("Error creating category:", error)
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "La categoría ya existe." })
    }
    res.status(500).json({ error: "Error al crear categoría." })
  }
})

app.put("/api/admin/categories/:id", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const { id } = req.params
    const { name } = req.body

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: "El nombre de la categoría es obligatorio." })
    }

    const [category] = await pool.query("SELECT id FROM categories WHERE id = ?", [id])

    if (category.length === 0) {
      return res.status(404).json({ error: "Categoría no encontrada." })
    }

    await pool.query("UPDATE categories SET name = ?, updated_at = NOW() WHERE id = ?", [name.trim(), id])

    await pool.query(
      `UPDATE courses
       SET category = ?
       WHERE category_id = ?`,
      [name.trim(), id],
    )

    res.json({ message: "Categoría actualizada exitosamente." })
  } catch (error) {
    console.error("Error updating category:", error)
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "La categoría ya existe." })
    }
    res.status(500).json({ error: "Error al actualizar categoría." })
  }
})

app.delete("/api/admin/categories/:id", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const { id } = req.params

    const [category] = await pool.query("SELECT id FROM categories WHERE id = ?", [id])

    if (category.length === 0) {
      return res.status(404).json({ error: "Categoría no encontrada." })
    }

    await pool.query("DELETE FROM categories WHERE id = ?", [id])

    res.json({ message: "Categoría eliminada exitosamente." })
  } catch (error) {
    console.error("Error deleting category:", error)
    res.status(500).json({ error: "Error al eliminar categoría." })
  }
})

app.get(
  "/api/instructor/course/:id/detail",
  authenticateToken,
  authorizeRole("instructor", "admin"),
  async (req, res) => {
    try {
      const { id } = req.params

      const [courses] = await pool.query(
        `SELECT c.*, u.first_name as instructor_first_name, u.last_name as instructor_last_name
       FROM courses c
       LEFT JOIN users u ON c.instructor_id = u.id
       WHERE c.id = ?`,
        [id],
      )

      if (courses.length === 0) {
        return res.status(404).json({ error: "Curso no encontrado." })
      }

      const course = courses[0]

      if (req.user.role === "instructor" && course.instructor_id !== req.user.id) {
        return res.status(403).json({ error: "No tienes permisos para ver este curso." })
      }

      const [students] = await pool.query(
        `SELECT sc.id as enrollment_id, sc.student_id, sc.enrolled_at, sc.progress, sc.score, sc.passed, sc.completed_at,
              u.id, u.email, u.first_name, u.last_name, u.employee_id
       FROM student_courses sc
       JOIN users u ON sc.student_id = u.id
       WHERE sc.course_id = ?
       ORDER BY u.first_name, u.last_name`,
        [id],
      )

      const totalEnrolled = students.length
      const totalPassed = students.filter((s) => s.passed).length
      const averageScore =
        students.length > 0 ? (students.reduce((sum, s) => sum + (s.score || 0), 0) / students.length).toFixed(2) : 0

      res.json({
        course,
        students,
        stats: {
          totalEnrolled,
          totalPassed,
          averageScore,
        },
      })
    } catch (error) {
      console.error("Error in /api/instructor/course/:id/detail:", error)
      res.status(500).json({ error: "Error al obtener detalles del curso." })
    }
  },
)

app.get("/api/categories", authenticateToken, async (req, res) => {
  try {
    const [categories] = await pool.query(
      `SELECT id, name
       FROM categories
       ORDER BY name`,
    )

    res.json({ categories })
  } catch (error) {
    console.error("Error in /api/categories:", error)
    res.status(500).json({ error: "Error al obtener categorías." })
  }
})

app.get("/api/admin/users/all", authenticateToken, authorizeRole("admin"), async (req, res) => {
  try {
    const [users] = await pool.query(
      `SELECT id, employee_id, email, first_name, last_name, role, created_at, is_active
       FROM users
       ORDER BY created_at DESC`,
    )

    res.json({ users })
  } catch (error) {
    console.error("Error fetching all users:", error)
    res.status(500).json({ error: "Error al obtener usuarios." })
  }
})

app.get("/api/categories/all", authenticateToken, async (req, res) => {
  try {
    const [categories] = await pool.query(`SELECT id, name FROM categories ORDER BY name ASC`)

    res.json({ categories })
  } catch (error) {
    console.error("Error fetching categories:", error)
    res.status(500).json({ error: "Error al obtener categorías." })
  }
})

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`)
  console.log(`📚 Learning UT Platform`)
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`)
})
