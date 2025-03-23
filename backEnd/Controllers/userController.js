const Usuario = require("../models/Usuario");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Registrar un nuevo usuario
const registerUser = async (req, res) => {
  try {
    const { nombre, ap, am, username, email, password, telefono, preguntaSecreta, respuestaSecreta } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const nuevoUsuario = new Usuario({
      nombre,
      ap,
      am,
      username,
      email,
      password: hashedPassword,
      telefono,
      preguntaSecreta,
      respuestaSecreta,
    });

    await nuevoUsuario.save();
    res.status(201).json({ mensaje: "Usuario registrado con éxito", usuario: nuevoUsuario });
  } catch (error) {
    res.status(500).json({ error: "Error al registrar usuario" });
  }
};

// Iniciar sesión
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const usuario = await Usuario.findOne({ email });
    if (!usuario) return res.status(400).json({ error: "Usuario no encontrado" });

    const esValida = await bcrypt.compare(password, usuario.password);
    if (!esValida) return res.status(400).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign({ id: usuario._id, rol: usuario.rol }, "secreto", { expiresIn: "1h" });
    res.json({ token, rol: usuario.rol, nombre: usuario.nombre });
  } catch (error) {
    res.status(500).json({ error: "Error en el servidor" });
  }
};

// Obtener todos los usuarios
const getUsuarios = async (req, res) => {
  try {
    const usuarios = await Usuario.find({}, { password: 0 });
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ error: "Error al obtener los usuarios" });
  }
};

// Actualizar el rol de un usuario
const updateRol = async (req, res) => {
  try {
    const { id } = req.params;
    const { rol } = req.body;

    const usuarioActualizado = await Usuario.findByIdAndUpdate(
      id,
      { rol },
      { new: true }
    );

    if (!usuarioActualizado) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json(usuarioActualizado);
  } catch (error) {
    res.status(500).json({ error: "Error al actualizar el rol" });
  }
};

// Eliminar un usuario
const deleteUsuario = async (req, res) => {
  try {
    const { id } = req.params;
    await Usuario.findByIdAndDelete(id);
    res.json({ mensaje: "Usuario eliminado correctamente" });
  } catch (error) {
    res.status(500).json({ error: "Error al eliminar el usuario" });
  }
};

// Verificar correo
const verificarCorreo = async (req, res) => {
  try {
    const { email } = req.body;
    const usuario = await Usuario.findOne({ email });

    if (!usuario) {
      return res.status(404).json({ error: "Correo no encontrado" });
    }

    res.json({ mensaje: "Correo válido", usuarioId: usuario._id });
  } catch (error) {
    res.status(500).json({ error: "Error al verificar el correo" });
  }
};

// Obtener pregunta secreta
const obtenerPregunta = async (req, res) => {
  try {
    const { email } = req.body;
    const usuario = await Usuario.findOne({ email }, { preguntaSecreta: 1 });

    if (!usuario) {
      return res.status(404).json({ error: "Correo no encontrado" });
    }

    res.json({ preguntaSecreta: usuario.preguntaSecreta });
  } catch (error) {
    res.status(500).json({ error: "Error al obtener la pregunta secreta" });
  }
};

// Verificar respuesta secreta
const verificarRespuesta = async (req, res) => {
  try {
    const { email, respuestaSecreta } = req.body;
    const usuario = await Usuario.findOne({ email });

    if (!usuario) {
      return res.status(404).json({ error: "Correo no encontrado" });
    }

    if (usuario.respuestaSecreta !== respuestaSecreta) {
      return res.status(400).json({ error: "Respuesta secreta incorrecta" });
    }

    res.json({ mensaje: "Respuesta válida" });
  } catch (error) {
    res.status(500).json({ error: "Error al verificar la respuesta secreta" });
  }
};

// Cambiar contraseña
const cambiarContrasena = async (req, res) => {
  try {
    const { email, nuevaContrasena } = req.body;
    const hashedPassword = await bcrypt.hash(nuevaContrasena, 10);

    const usuario = await Usuario.findOneAndUpdate(
      { email },
      { password: hashedPassword },
      { new: true }
    );

    if (!usuario) {
      return res.status(404).json({ error: "Correo no encontrado" });
    }

    res.json({ mensaje: "Contraseña actualizada con éxito" });
  } catch (error) {
    res.status(500).json({ error: "Error al cambiar la contraseña" });
  }
};

module.exports = {
  registerUser,
  loginUser,
  getUsuarios,
  updateRol,
  deleteUsuario,
  verificarCorreo,
  obtenerPregunta,
  verificarRespuesta,
  cambiarContrasena,
};
