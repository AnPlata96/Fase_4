from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
import io
import logging
import os
import re
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from typing import Any, Dict, List, Optional, Tuple


# ==================================================================================================
# 1. CONFIGURACIÓN DEL SISTEMA DE AUDITORÍA Y REGISTRO DE EVENTOS (LOGS)
# ==================================================================================================
DIRECTORIO_ACTUAL = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_LOG = os.path.join(DIRECTORIO_ACTUAL, "software_fj.log")

# Creación y configuración del logger principal del sistema
logger = logging.getLogger("SoftwareFJ")
logger.setLevel(logging.DEBUG)

if logger.hasHandlers():
    logger.handlers.clear()

formato_log = logging.Formatter(
    fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Handler persistente para archivo físico
file_handler = logging.FileHandler(ARCHIVO_LOG, mode="a", encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formato_log)
logger.addHandler(file_handler)

# Handler para consola
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.CRITICAL)
console_handler.setFormatter(formato_log)
logger.addHandler(console_handler)

logger.info("=== INICIO DE SESIÓN DEL SISTEMA SOFTWARE FJ ===")


# ==================================================================================================
# 2. JERARQUÍA DE EXCEPCIONES PERSONALIZADAS
# ==================================================================================================
class SoftwareFJError(Exception):
    """Excepción raíz para todas las anomalías y errores del ecosistema Software FJ."""

    def __init__(self, mensaje: str, codigo_error: str = "ERR-GEN-00"):
        super().__init__(f"[{codigo_error}] {mensaje}")
        self.mensaje = mensaje
        self.codigo_error = codigo_error


class DatoInvalidoError(SoftwareFJError):
    """Lanzada cuando un dato de entrada no cumple con los formatos, tipos o rangos requeridos."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-DAT-01")


class ParametroFaltanteError(SoftwareFJError):
    """Lanzada cuando se omite un parámetro obligatorio o se proporcionan valores vacíos/nulos."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-PAR-02")


class ServicioNoDisponibleError(SoftwareFJError):
    """Lanzada al intentar operar, reservar o liquidar un servicio que está inactivo o fuera de servicio."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-SER-03")


class ReservaInvalidaError(SoftwareFJError):
    """Lanzada cuando los parámetros de una reserva son ilógicos (ej. duración <= 0 horas)."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-RES-04")


class OperacionNoPermitidaError(SoftwareFJError):
    """Lanzada cuando se intenta una transición de estado ilegal (ej. cancelar una reserva cancelada)."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-OPE-05")


class CalculoInconsistenteError(SoftwareFJError):
    """Lanzada cuando un cálculo financiero produce inconsistencias matemáticas (ej. descuentos > 100%)."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-CAL-06")


class RegistroDuplicadoError(SoftwareFJError):
    """Lanzada al intentar registrar un cliente, servicio o reserva con un identificador preexistente."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-DUP-07")


class EntidadNoEncontradaError(SoftwareFJError):
    """Lanzada cuando se consulta una entidad inexistente en las colecciones en memoria."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-NOT-08")


class CredencialesInvalidasError(SoftwareFJError):
    """Lanzada cuando la autenticación del usuario falla por credenciales incorrectas."""

    def __init__(self, mensaje: str):
        super().__init__(mensaje, codigo_error="ERR-AUT-09")


# ==================================================================================================
# 3. ENUMERACIONES Y ESTADOS
# ==================================================================================================
class EstadoReserva(Enum):
    """Estados controlados del ciclo de vida de una reserva."""
    PENDIENTE = "PENDIENTE"
    CONFIRMADA = "CONFIRMADA"
    CANCELADA = "CANCELADA"
    FINALIZADA = "FINALIZADA"


# ==================================================================================================
# 4. MÓDULO DE SEGURIDAD Y AUTENTICACIÓN (LOGIN)
# ==================================================================================================
class GestorAutenticacion:
    """
    Gestiona el control de acceso, validación de credenciales y límite de intentos de sesión.
    Demuestra encapsulación y control estricto de excepciones.
    """

    # Diccionario de credenciales preestablecidas (usuario: clave)
    USUARIOS_REGISTRADOS: Dict[str, str] = {
        "admin": "admin123",
        "programacion": "programacion",
        "pablo.plata": "unad2026",
        "docente": "unad213023",
        "softwarefj": "fj2026"
    }

    def __init__(self, max_intentos: int = 3):
        self._max_intentos: int = max_intentos
        self._intentos_fallidos: int = 0
        self._bloqueado: bool = False
        self._usuario_actual: Optional[str] = None

    @property
    def intentos_fallidos(self) -> int:
        return self._intentos_fallidos

    @property
    def bloqueado(self) -> bool:
        return self._bloqueado

    @property
    def usuario_actual(self) -> Optional[str]:
        return self._usuario_actual

    def autenticar(self, usuario: str, contrasena: str) -> bool:
        """
        Valida las credenciales ingresadas.
        Lanza OperacionNoPermitidaError si está bloqueado,
        ParametroFaltanteError si faltan campos,
        o CredencialesInvalidasError si no coinciden.
        """
        if self._bloqueado:
            logger.critical("Acceso denegado: Sistema bloqueado por exceso de intentos de inicio de sesión.")
            raise OperacionNoPermitidaError(
                "El sistema de autenticación se encuentra BLOQUEADO temporalmente por superar el límite de intentos."
            )

        usuario_limpio = str(usuario).strip().lower()
        contrasena_limpia = str(contrasena).strip()

        if not usuario_limpio or not contrasena_limpia:
            logger.warning("Fallo en login: Usuario o contraseña vacíos.")
            raise ParametroFaltanteError("Debe suministrar tanto el nombre de usuario como la contraseña.")

        # Verificación en catálogo de usuarios
        if usuario_limpio in self.USUARIOS_REGISTRADOS and self.USUARIOS_REGISTRADOS[usuario_limpio] == contrasena_limpia:
            self._intentos_fallidos = 0
            self._usuario_actual = usuario_limpio
            logger.info(f"Autenticación exitosa para el usuario '{usuario_limpio}'.")
            return True
        else:
            self._intentos_fallidos += 1
            restantes = max(0, self._max_intentos - self._intentos_fallidos)
            logger.warning(
                f"Fallo de autenticación para '{usuario_limpio}'. Intento {self._intentos_fallidos}/{self._max_intentos}."
            )

            if self._intentos_fallidos >= self._max_intentos:
                self._bloqueado = True
                logger.critical(f"Usuario '{usuario_limpio}' bloqueó el acceso tras 3 intentos fallidos.")
                raise OperacionNoPermitidaError(
                    "Ha superado el número máximo de intentos fallidos (3). El sistema se ha bloqueado por seguridad."
                )

            raise CredencialesInvalidasError(
                f"Credenciales de acceso incorrectas. Le quedan {restantes} intento(s)."
            )

    def reiniciar_bloqueo(self) -> None:
        """Permite desbloquear administrativamente el sistema de login."""
        self._intentos_fallidos = 0
        self._bloqueado = False
        logger.info("El sistema de autenticación ha sido desbloqueado exitosamente.")


# ==================================================================================================
# 5. CLASE ABSTRACTA BASE PARA TODAS LAS ENTIDADES
# ==================================================================================================
class EntidadBase(ABC):
    """
    Clase abstracta que define las propiedades y comportamientos comunes de todas las
    entidades dentro del ecosistema de Software FJ (Clientes, Servicios, Reservas).
    """

    def __init__(self, id_entidad: str):
        if not id_entidad or not str(id_entidad).strip():
            logger.error("Intento de crear EntidadBase con identificador nulo o vacío.")
            raise ParametroFaltanteError("El identificador de la entidad no puede estar vacío.")

        self._id_entidad: str = str(id_entidad).strip().upper()
        self._fecha_registro: datetime = datetime.now()
        self._activo: bool = True

    @property
    def id_entidad(self) -> str:
        return self._id_entidad

    @property
    def fecha_registro(self) -> datetime:
        return self._fecha_registro

    @property
    def activo(self) -> bool:
        return self._activo

    @activo.setter
    def activo(self, valor: bool) -> None:
        if not isinstance(valor, bool):
            raise DatoInvalidoError("El valor del estado 'activo' debe ser un booleano (True/False).")
        self._activo = valor
        logger.info(f"Entidad {self._id_entidad}: estado de disponibilidad modificado a {valor}.")

    @abstractmethod
    def obtener_detalle(self) -> str:
        """Retorna una cadena informativa de la entidad."""
        pass

    @abstractmethod
    def validar_integridad(self) -> bool:
        """Valida que los atributos internos cumplan las reglas de consistencia del negocio."""
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self._id_entidad} activo={self._activo}>"


# ==================================================================================================
# 6. CLASE CLIENTE CON ENCAPSULACIÓN Y VALIDACIONES ROBUSTAS
# ==================================================================================================
class Cliente(EntidadBase):
    """
    Representa a un cliente en Software FJ con encapsulación estricta de sus datos personales
    y validaciones mediante expresiones regulares y reglas de negocio.
    """

    def __init__(self, identificacion: str, nombre_completo: str, correo: str, telefono: str):
        super().__init__(id_entidad=identificacion)

        self._identificacion: str = ""
        self._nombre_completo: str = ""
        self._correo: str = ""
        self._telefono: str = ""

        # Asignación a través de setters que validan cada campo
        self.identificacion = identificacion
        self.nombre_completo = nombre_completo
        self.correo = correo
        self.telefono = telefono

        logger.info(f"Cliente registrado con éxito: {self._nombre_completo} [C.C.: {self._identificacion}].")

    # --- Encapsulación de Identificación ---
    @property
    def identificacion(self) -> str:
        return self._identificacion

    @identificacion.setter
    def identificacion(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            logger.error("Validación fallida: Identificación vacía.")
            raise ParametroFaltanteError("La identificación del cliente es un campo obligatorio.")

        valor_limpio = str(valor).strip()
        if not valor_limpio.isdigit() or not (6 <= len(valor_limpio) <= 12):
            logger.warning(f"Validación fallida: Identificación '{valor}' debe ser numérica entre 6 y 12 dígitos.")
            raise DatoInvalidoError(
                f"La identificación '{valor}' no es válida. Debe contener únicamente entre 6 y 12 dígitos numéricos."
            )
        self._identificacion = valor_limpio

    # --- Encapsulación de Nombre Completo ---
    @property
    def nombre_completo(self) -> str:
        return self._nombre_completo

    @nombre_completo.setter
    def nombre_completo(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            logger.error("Validación fallida: Nombre de cliente vacío.")
            raise ParametroFaltanteError("El nombre completo del cliente es un campo obligatorio.")

        valor_limpio = str(valor).strip()
        patron_nombre = r"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s\.\']{3,80}$"
        if not re.match(patron_nombre, valor_limpio):
            logger.warning(f"Validación fallida: Nombre '{valor}' contiene caracteres inválidos o longitud errónea.")
            raise DatoInvalidoError(
                f"El nombre '{valor}' no es válido. Debe contener al menos 3 letras y no incluir números."
            )
        self._nombre_completo = valor_limpio

    # --- Encapsulación de Correo Electrónico ---
    @property
    def correo(self) -> str:
        return self._correo

    @correo.setter
    def correo(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            logger.error("Validación fallida: Correo electrónico vacío.")
            raise ParametroFaltanteError("El correo electrónico es un campo obligatorio.")

        valor_limpio = str(valor).strip().lower()
        patron_email = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(patron_email, valor_limpio):
            logger.warning(f"Validación fallida: Formato de correo '{valor}' inválido.")
            raise DatoInvalidoError(
                f"El correo electrónico '{valor}' no tiene una estructura válida (ejemplo: usuario@dominio.com)."
            )
        self._correo = valor_limpio

    # --- Encapsulación de Teléfono ---
    @property
    def telefono(self) -> str:
        return self._telefono

    @telefono.setter
    def telefono(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            logger.error("Validación fallida: Teléfono vacío.")
            raise ParametroFaltanteError("El número de teléfono es un campo obligatorio.")

        valor_limpio = str(valor).strip()
        if not valor_limpio.isdigit() or len(valor_limpio) != 10:
            logger.warning(f"Validación fallida: Teléfono '{valor}' debe tener 10 dígitos numéricos.")
            raise DatoInvalidoError(
                f"El teléfono '{valor}' no es válido. Debe contener exactamente 10 dígitos numéricos."
            )
        self._telefono = valor_limpio

    def obtener_detalle(self) -> str:
        estado_str = "ACTIVO" if self._activo else "INACTIVO"
        return (
            f"Cliente: {self._nombre_completo} | C.C./ID: {self._identificacion} | "
            f"Email: {self._correo} | Tel: {self._telefono} | Estado: {estado_str}"
        )

    def validar_integridad(self) -> bool:
        return (
            bool(self._identificacion)
            and bool(self._nombre_completo)
            and "@" in self._correo
            and len(self._telefono) == 10
        )


# ==================================================================================================
# 7. CLASE ABSTRACTA SERVICIO Y MÉTODOS SOBRECARGADOS
# ==================================================================================================
class Servicio(EntidadBase, ABC):
    """
    Clase abstracta que define el contrato común para todos los servicios de Software FJ.
    Declara métodos polimórficos de cálculo de costo, descripción y validación de parámetros.
    """

    def __init__(self, id_servicio: str, nombre_servicio: str, tarifa_base_hora: float):
        super().__init__(id_entidad=id_servicio)

        self._nombre_servicio: str = ""
        self._tarifa_base_hora: float = 0.0

        self.nombre_servicio = nombre_servicio
        self.tarifa_base_hora = tarifa_base_hora

    @property
    def id_servicio(self) -> str:
        return self.id_entidad

    @property
    def nombre_servicio(self) -> str:
        return self._nombre_servicio

    @nombre_servicio.setter
    def nombre_servicio(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            logger.error("Validación fallida: Nombre de servicio vacío.")
            raise ParametroFaltanteError("El nombre del servicio no puede ser nulo ni vacío.")
        self._nombre_servicio = str(valor).strip()

    @property
    def tarifa_base_hora(self) -> float:
        return self._tarifa_base_hora

    @tarifa_base_hora.setter
    def tarifa_base_hora(self, valor: Any) -> None:
        try:
            tarifa_num = float(valor)
        except (ValueError, TypeError) as exc:
            logger.error(f"Error de conversión en tarifa_base_hora: {valor}. Encadenando excepción.")
            # ENCADENAMIENTO DE EXCEPCIONES: raise ... from ...
            raise DatoInvalidoError(f"La tarifa por hora debe ser un número válido. Recibido: {valor}") from exc

        if tarifa_num <= 0:
            logger.error(f"Validación fallida: Tarifa por hora ({tarifa_num}) no positiva.")
            raise DatoInvalidoError("La tarifa base por hora debe ser estrictamente mayor a cero.")

        self._tarifa_base_hora = tarifa_num

    # --- Métodos Polimórficos Abstractos ---
    @abstractmethod
    def calcular_costo(self, duracion_horas: float, **kwargs) -> float:
        """Calcula el costo neto del servicio según su naturaleza y duración."""
        pass

    @abstractmethod
    def describir_servicio(self) -> str:
        """Retorna la ficha técnica y alcance detallado del servicio."""
        pass

    @abstractmethod
    def validar_parametros(self) -> bool:
        """Verifica que los parámetros específicos del servicio sean consistentes."""
        pass

    def obtener_detalle(self) -> str:
        return self.describir_servicio()

    def validar_integridad(self) -> bool:
        return bool(self._id_entidad) and self._tarifa_base_hora > 0 and self.validar_parametros()

    # --- Método Sobrecargado de Costos ---
    def calcular_costo_sobrecargado(
        self,
        duracion_horas: float,
        porcentaje_impuesto: float = 0.19,
        porcentaje_descuento: float = 0.0,
        seguro_adicional: float = 0.0,
        cupon_promocional: Optional[str] = None,
        **kwargs
    ) -> Dict[str, float]:
        """
        MÉTODO SOBRECARGADO: Soporta múltiples combinaciones de parámetros de facturación:
          1. Solo horas de duración.
          2. Horas + Descuento porcentual.
          3. Horas + Impuestos (IVA 19% por defecto o personalizado).
          4. Horas + Descuentos + Cupones promocionales + Seguros opcionales.
        """
        if duracion_horas <= 0:
            raise ReservaInvalidaError("La duración para el cálculo de costos debe ser mayor a 0 horas.")

        # Validación de consistencia matemática
        if not (0.0 <= porcentaje_descuento <= 1.0):
            logger.error(f"Inconsistencia en descuento: {porcentaje_descuento} fuera de rango [0, 1].")
            try:
                raise ValueError("El porcentaje de descuento debe situarse estrictamente entre 0.0 (0%) y 1.0 (100%).")
            except ValueError as err_val:
                # ENCADENAMIENTO DE EXCEPCIONES: raise ... from ...
                raise CalculoInconsistenteError(
                    f"Cálculo inconsistente detectado: Descuento del {porcentaje_descuento*100}% no permitido."
                ) from err_val

        if porcentaje_impuesto < 0.0:
            raise CalculoInconsistenteError("El porcentaje de impuesto no puede ser un valor negativo.")

        if seguro_adicional < 0.0:
            raise CalculoInconsistenteError("El seguro adicional no puede ser negativo.")

        # Invocación polimórfica del costo base
        subtotal_base = self.calcular_costo(duracion_horas, **kwargs)

        # Aplicación de cupones
        descuento_cupon = 0.0
        if cupon_promocional:
            cupon_normalizado = str(cupon_promocional).strip().upper()
            if cupon_normalizado == "FJ2026":
                descuento_cupon = subtotal_base * 0.10
                logger.info(f"Cupón 'FJ2026' aplicado sobre servicio {self.id_servicio} (10% desc).")
            elif cupon_normalizado == "ESTUDIANTE":
                descuento_cupon = subtotal_base * 0.15
                logger.info(f"Cupón 'ESTUDIANTE' aplicado sobre servicio {self.id_servicio} (15% desc).")
            else:
                logger.warning(f"Cupón '{cupon_promocional}' no reconocido; sin descuento adicional.")

        monto_descuento_base = subtotal_base * porcentaje_descuento
        total_descuento = monto_descuento_base + descuento_cupon

        if total_descuento > subtotal_base:
            total_descuento = subtotal_base

        base_gravable = (subtotal_base - total_descuento) + seguro_adicional
        monto_impuesto = base_gravable * porcentaje_impuesto
        total_final = base_gravable + monto_impuesto

        resultado = {
            "duracion_horas": duracion_horas,
            "subtotal_base": round(subtotal_base, 2),
            "descuento_aplicado": round(total_descuento, 2),
            "seguro_adicional": round(seguro_adicional, 2),
            "base_gravable": round(base_gravable, 2),
            "impuesto_iva": round(monto_impuesto, 2),
            "total_final": round(total_final, 2),
        }
        logger.debug(f"Cálculo sobrecargado finalizado para {self.id_servicio}: {resultado}")
        return resultado


# ==================================================================================================
# 8. SERVICIOS ESPECIALIZADOS (CLASES DERIVADAS Y POLIMORFISMO)
# ==================================================================================================

# --- Servicio 1: Reserva de Salas ---
class ReservaSala(Servicio):
    """
    Servicio especializado en alquiler de salas de conferencias, juntas y capacitación.
    Implementa polimorfismo según capacidad de personas y equipamiento audiovisual.
    """

    def __init__(
        self,
        id_servicio: str,
        nombre_servicio: str,
        tarifa_base_hora: float,
        capacidad_personas: int,
        tiene_proyector: bool = True,
        tiene_aire_acondicionado: bool = True
    ):
        super().__init__(id_servicio, nombre_servicio, tarifa_base_hora)

        self._capacidad_personas: int = 0
        self._tiene_proyector: bool = tiene_proyector
        self._tiene_aire_acondicionado: bool = tiene_aire_acondicionado

        self.capacidad_personas = capacidad_personas
        self.validar_parametros()
        logger.info(f"Servicio de Sala registrado: {self._nombre_servicio} (Capacidad: {self._capacidad_personas} pers).")

    @property
    def capacidad_personas(self) -> int:
        return self._capacidad_personas

    @capacidad_personas.setter
    def capacidad_personas(self, valor: Any) -> None:
        try:
            capacidad_num = int(valor)
        except (ValueError, TypeError) as exc:
            raise DatoInvalidoError(f"La capacidad de personas debe ser un número entero. Recibido: {valor}") from exc

        if capacidad_num <= 0:
            raise DatoInvalidoError(f"La capacidad de la sala debe ser mayor a 0 personas. Recibido: {capacidad_num}")
        self._capacidad_personas = capacidad_num

    @property
    def tiene_proyector(self) -> bool:
        return self._tiene_proyector

    @property
    def tiene_aire_acondicionado(self) -> bool:
        return self._tiene_aire_acondicionado

    # Polimorfismo: Sobrescritura de calcular_costo
    def calcular_costo(self, duracion_horas: float, **kwargs) -> float:
        if duracion_horas <= 0:
            raise ReservaInvalidaError("La duración de reserva de la sala debe ser superior a cero horas.")

        costo_base = self._tarifa_base_hora * duracion_horas
        recargo_capacidad = 0.15 if self._capacidad_personas > 15 else 0.0
        costo_proyector = (12000.0 * duracion_horas) if self._tiene_proyector else 0.0

        subtotal = (costo_base * (1.0 + recargo_capacidad)) + costo_proyector
        return round(subtotal, 2)

    # Polimorfismo: Sobrescritura de describir_servicio
    def describir_servicio(self) -> str:
        proy_txt = "Sí" if self._tiene_proyector else "No"
        aire_txt = "Sí" if self._tiene_aire_acondicionado else "No"
        return (
            f"[SALA] {self._nombre_servicio} (ID: {self._id_entidad}) | Capacidad: {self._capacidad_personas} pers | "
            f"Tarifa: ${self._tarifa_base_hora:,.2f}/h | Proyector: {proy_txt} | A/C: {aire_txt}"
        )

    # Polimorfismo: Sobrescritura de validar_parametros
    def validar_parametros(self) -> bool:
        if self._capacidad_personas <= 0 or self._tarifa_base_hora <= 0:
            raise DatoInvalidoError("Parámetros de sala inconsistentes (capacidad o tarifa no positivas).")
        return True


# --- Servicio 2: Alquiler de Equipos ---
class AlquilerEquipo(Servicio):
    """
    Servicio especializado en el préstamo y alquiler de equipos de cómputo y audiovisuales.
    Aplica depósito en garantía reembolsable y opción de seguro de protección de hardware.
    """

    def __init__(
        self,
        id_servicio: str,
        nombre_servicio: str,
        tarifa_base_hora: float,
        marca_modelo: str,
        tipo_equipo: str,
        deposito_garantia: float
    ):
        super().__init__(id_servicio, nombre_servicio, tarifa_base_hora)

        self._marca_modelo: str = ""
        self._tipo_equipo: str = ""
        self._deposito_garantia: float = 0.0

        self.marca_modelo = marca_modelo
        self.tipo_equipo = tipo_equipo
        self.deposito_garantia = deposito_garantia

        self.validar_parametros()
        logger.info(f"Servicio de Alquiler de Equipo registrado: {self._nombre_servicio} ({self._marca_modelo}).")

    @property
    def marca_modelo(self) -> str:
        return self._marca_modelo

    @marca_modelo.setter
    def marca_modelo(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            raise ParametroFaltanteError("La marca y modelo del equipo son obligatorios.")
        self._marca_modelo = str(valor).strip()

    @property
    def tipo_equipo(self) -> str:
        return self._tipo_equipo

    @tipo_equipo.setter
    def tipo_equipo(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            raise ParametroFaltanteError("El tipo de equipo es obligatorio.")
        self._tipo_equipo = str(valor).strip()

    @property
    def deposito_garantia(self) -> float:
        return self._deposito_garantia

    @deposito_garantia.setter
    def deposito_garantia(self, valor: Any) -> None:
        try:
            deposito_num = float(valor)
        except (ValueError, TypeError) as exc:
            raise DatoInvalidoError(f"El depósito de garantía debe ser numérico. Recibido: {valor}") from exc

        if deposito_num < 0:
            raise DatoInvalidoError("El depósito de garantía no puede ser un valor negativo.")
        self._deposito_garantia = deposito_num

    # Polimorfismo: Sobrescritura de calcular_costo
    def calcular_costo(self, duracion_horas: float, **kwargs) -> float:
        if duracion_horas <= 0:
            raise ReservaInvalidaError("La duración del alquiler del equipo debe ser mayor a cero horas.")

        costo_alquiler = self._tarifa_base_hora * duracion_horas
        incluir_seguro = kwargs.get("incluir_seguro", False)
        costo_seguro = (costo_alquiler * 0.12) if incluir_seguro else 0.0

        return round(costo_alquiler + costo_seguro, 2)

    # Polimorfismo: Sobrescritura de describir_servicio
    def describir_servicio(self) -> str:
        return (
            f"[EQUIPO] {self._nombre_servicio} (ID: {self._id_entidad}) | Modelo: {self._marca_modelo} | "
            f"Tipo: {self._tipo_equipo} | Tarifa: ${self._tarifa_base_hora:,.2f}/h | "
            f"Garantía: ${self._deposito_garantia:,.2f}"
        )

    # Polimorfismo: Sobrescritura de validar_parametros
    def validar_parametros(self) -> bool:
        if self._deposito_garantia < 0 or not self._marca_modelo:
            raise DatoInvalidoError("Parámetros del equipo no válidos (garantía negativa o marca vacía).")
        return True


# --- Servicio 3: Asesorías Especializadas ---
class AsesoriaEspecializada(Servicio):
    """
    Servicio de consultoría en desarrollo de software, arquitectura cloud y ciberseguridad.
    Aplica multiplicadores según el seniority del consultor y costo de informes técnicos formales.
    """

    NIVELES_PERMITIDOS = {
        "JUNIOR": 1.0,
        "SENIOR": 1.4,
        "MASTER": 1.85,
    }

    def __init__(
        self,
        id_servicio: str,
        nombre_servicio: str,
        tarifa_base_hora: float,
        area_experiencia: str,
        nivel_consultor: str
    ):
        super().__init__(id_servicio, nombre_servicio, tarifa_base_hora)

        self._area_experiencia: str = ""
        self._nivel_consultor: str = ""

        self.area_experiencia = area_experiencia
        self.nivel_consultor = nivel_consultor

        self.validar_parametros()
        logger.info(f"Asesoría Especializada registrada: {self._nombre_servicio} [Nivel: {self._nivel_consultor}].")

    @property
    def area_experiencia(self) -> str:
        return self._area_experiencia

    @area_experiencia.setter
    def area_experiencia(self, valor: str) -> None:
        if not valor or not str(valor).strip():
            raise ParametroFaltanteError("El área de experiencia técnica es obligatoria.")
        self._area_experiencia = str(valor).strip()

    @property
    def nivel_consultor(self) -> str:
        return self._nivel_consultor

    @nivel_consultor.setter
    def nivel_consultor(self, valor: str) -> None:
        if not valor:
            raise ParametroFaltanteError("El nivel del consultor es obligatorio.")
        valor_normalizado = str(valor).strip().upper()
        if valor_normalizado not in self.NIVELES_PERMITIDOS:
            opciones = ", ".join(self.NIVELES_PERMITIDOS.keys())
            raise DatoInvalidoError(
                f"Nivel de consultor '{valor}' no permitido. Opciones válidas: {opciones}."
            )
        self._nivel_consultor = valor_normalizado

    # Polimorfismo: Sobrescritura de calcular_costo
    def calcular_costo(self, duracion_horas: float, **kwargs) -> float:
        if duracion_horas <= 0:
            raise ReservaInvalidaError("La duración de la asesoría debe ser superior a cero horas.")

        multiplicador = self.NIVELES_PERMITIDOS[self._nivel_consultor]
        costo_honorarios = self._tarifa_base_hora * duracion_horas * multiplicador
        incluye_informe = kwargs.get("incluye_informe", False)
        costo_informe = 60000.0 if incluye_informe else 0.0

        return round(costo_honorarios + costo_informe, 2)

    # Polimorfismo: Sobrescritura de describir_servicio
    def describir_servicio(self) -> str:
        return (
            f"[ASESORÍA] {self._nombre_servicio} (ID: {self._id_entidad}) | Área: {self._area_experiencia} | "
            f"Nivel: {self._nivel_consultor} (Factor x{self.NIVELES_PERMITIDOS[self._nivel_consultor]}) | "
            f"Tarifa Base: ${self._tarifa_base_hora:,.2f}/h"
        )

    # Polimorfismo: Sobrescritura de validar_parametros
    def validar_parametros(self) -> bool:
        if self._nivel_consultor not in self.NIVELES_PERMITIDOS or not self._area_experiencia:
            raise DatoInvalidoError("Parámetros de asesoría incompletos o nivel inválido.")
        return True


# ==================================================================================================
# 9. CLASE RESERVA CON GESTIÓN DE ESTADOS Y MANEJO RIGUROSO DE EXCEPCIONES
# ==================================================================================================
class Reserva(EntidadBase):
    """
    Integra cliente, servicio, duración y estado. Implementa confirmación,
    cancelación y procesamiento con control riguroso de excepciones (try/except/else/finally).
    """

    def __init__(
        self,
        codigo_reserva: str,
        cliente: Cliente,
        servicio: Servicio,
        duracion_horas: float,
        observaciones: str = ""
    ):
        super().__init__(id_entidad=codigo_reserva)

        if not isinstance(cliente, Cliente):
            raise DatoInvalidoError("El cliente asociado a la reserva debe ser una instancia de Cliente.")
        if not isinstance(servicio, Servicio):
            raise DatoInvalidoError("El servicio asociado a la reserva debe ser una instancia de Servicio.")

        self._cliente: Cliente = cliente
        self._servicio: Servicio = servicio
        self._duracion_horas: float = 0.0
        self._estado: EstadoReserva = EstadoReserva.PENDIENTE
        self._observaciones: str = str(observaciones).strip()
        self._costo_total: float = 0.0
        self._desglose_financiero: Dict[str, float] = {}

        self.duracion_horas = duracion_horas

        if not self._servicio.activo:
            logger.error(f"Intento de reserva para servicio no disponible: {self._servicio.id_servicio}.")
            raise ServicioNoDisponibleError(
                f"El servicio '{self._servicio.nombre_servicio}' [ID: {self._servicio.id_servicio}] "
                f"no se encuentra activo ni disponible para nuevas reservas."
            )

        logger.info(
            f"Reserva creada: {self.id_entidad} | Cliente: {self._cliente.nombre_completo} | "
            f"Servicio: {self._servicio.nombre_servicio} | Estado inicial: {self._estado.value}."
        )

    @property
    def codigo_reserva(self) -> str:
        return self.id_entidad

    @property
    def cliente(self) -> Cliente:
        return self._cliente

    @property
    def servicio(self) -> Servicio:
        return self._servicio

    @property
    def duracion_horas(self) -> float:
        return self._duracion_horas

    @duracion_horas.setter
    def duracion_horas(self, valor: Any) -> None:
        try:
            duracion_num = float(valor)
        except (ValueError, TypeError) as exc:
            logger.error(f"Error de conversión en duracion_horas: {valor}. Encadenando excepción.")
            raise ReservaInvalidaError(f"La duración de la reserva debe ser un número válido. Recibido: {valor}") from exc

        if duracion_num <= 0:
            logger.error(f"Validación fallida: Duración inválida ({duracion_num} horas).")
            raise ReservaInvalidaError(
                f"La duración de la reserva debe ser estrictamente mayor a 0 horas. Valor recibido: {duracion_num}"
            )
        self._duracion_horas = duracion_num

    @property
    def estado(self) -> EstadoReserva:
        return self._estado

    @property
    def observaciones(self) -> str:
        return self._observaciones

    @property
    def costo_total(self) -> float:
        return self._costo_total

    @property
    def desglose_financiero(self) -> Dict[str, float]:
        return self._desglose_financiero

    # --- Estructura try / except / else / finally para Confirmación ---
    def confirmar(self) -> None:
        auditoria_exitosa = False
        try:
            logger.info(f"Iniciando confirmación de reserva {self.id_entidad}...")
            if self._estado != EstadoReserva.PENDIENTE:
                raise OperacionNoPermitidaError(
                    f"No se puede confirmar la reserva {self.id_entidad} porque su estado actual es '{self._estado.value}'. "
                    f"Solo se permiten reservas en estado PENDIENTE."
                )

            if not self._servicio.activo:
                raise ServicioNoDisponibleError(
                    f"No se puede confirmar la reserva: El servicio {self._servicio.id_servicio} ha dejado de estar activo."
                )

            self._estado = EstadoReserva.CONFIRMADA
            auditoria_exitosa = True

        except (OperacionNoPermitidaError, ServicioNoDisponibleError) as error_negocio:
            logger.error(f"Fallo al confirmar reserva {self.id_entidad}: {error_negocio}")
            raise

        else:
            # Bloque else: Se ejecuta únicamente si no se levantó ninguna excepción
            logger.info(f"Reserva {self.id_entidad} confirmada satisfactoriamente (Bloque 'else' ejecutado).")

        finally:
            # Bloque finally: Garantiza siempre la auditoría del proceso
            logger.debug(
                f"Auditoría post-confirmación reserva {self.id_entidad}: Operación completada={auditoria_exitosa}."
            )

    # --- Método de Cancelación ---
    def cancelar(self, motivo: str = "Solicitud del cliente") -> None:
        try:
            if self._estado == EstadoReserva.CANCELADA:
                raise OperacionNoPermitidaError(
                    f"La reserva {self.id_entidad} ya se encuentra CANCELADA. Operación redundante no permitida."
                )

            if self._estado == EstadoReserva.FINALIZADA:
                raise OperacionNoPermitidaError(
                    f"No se puede cancelar la reserva {self.id_entidad} porque ya ha sido FINALIZADA y liquidada."
                )

            self._estado = EstadoReserva.CANCELADA
            self._observaciones += f" | CANCELADA: {motivo}"
            logger.warning(f"Reserva {self.id_entidad} cancelada. Motivo: {motivo}")

        except OperacionNoPermitidaError as err_canc:
            logger.error(f"Error en cancelación de reserva {self.id_entidad}: {err_canc}")
            raise

    # --- Estructura try / except / else / finally para Procesamiento ---
    def procesar(
        self,
        porcentaje_impuesto: float = 0.19,
        porcentaje_descuento: float = 0.0,
        seguro_adicional: float = 0.0,
        cupon: Optional[str] = None,
        **kwargs
    ) -> Dict[str, float]:
        resultado_financiero: Dict[str, float] = {}
        try:
            logger.info(f"Iniciando procesamiento y facturación de reserva {self.id_entidad}...")

            if self._estado != EstadoReserva.CONFIRMADA:
                raise OperacionNoPermitidaError(
                    f"No es posible procesar la reserva {self.id_entidad} con estado '{self._estado.value}'. "
                    f"La reserva debe estar en estado CONFIRMADA para ser procesada."
                )

            resultado_financiero = self._servicio.calcular_costo_sobrecargado(
                duracion_horas=self._duracion_horas,
                porcentaje_impuesto=porcentaje_impuesto,
                porcentaje_descuento=porcentaje_descuento,
                seguro_adicional=seguro_adicional,
                cupon_promocional=cupon,
                **kwargs
            )

            self._desglose_financiero = resultado_financiero
            self._costo_total = resultado_financiero["total_final"]
            self._estado = EstadoReserva.FINALIZADA

        except (OperacionNoPermitidaError, CalculoInconsistenteError, ReservaInvalidaError) as err_proc:
            logger.error(f"Excepción al procesar reserva {self.id_entidad}: {err_proc}")
            raise

        else:
            logger.info(
                f"Reserva {self.id_entidad} liquidada con éxito por un total de "
                f"${self._costo_total:,.2f} COP (Bloque 'else')."
            )
            return resultado_financiero

        finally:
            logger.debug(f"Fin del ciclo de procesamiento para la reserva {self.id_entidad} (Bloque 'finally').")

    def obtener_detalle(self) -> str:
        costo_str = f"${self._costo_total:,.2f} COP" if self._costo_total > 0 else "Sin liquidar"
        return (
            f"Reserva [{self.id_entidad}] | Estado: {self._estado.value} | "
            f"Cliente: {self._cliente.nombre_completo} (C.C. {self._cliente.identificacion}) | "
            f"Servicio: {self._servicio.nombre_servicio} | Duración: {self._duracion_horas}h | "
            f"Total: {costo_str}"
        )

    def validar_integridad(self) -> bool:
        return (
            bool(self.id_entidad)
            and self._cliente is not None
            and self._servicio is not None
            and self._duracion_horas > 0
        )


# ==================================================================================================
# 10. GESTOR CENTRAL DEL SISTEMA (SIN BASE DE DATOS - LISTAS INTERNAS)
# ==================================================================================================
class SistemaGestionFJ:
    """
    Controlador central del sistema. Mantiene colecciones internas en memoria
    para clientes, servicios y reservas, asegurando validaciones y registro en logs.
    """

    def __init__(self):
        self._clientes: List[Cliente] = []
        self._servicios: List[Servicio] = []
        self._reservas: List[Reserva] = []
        logger.info("SistemaGestionFJ inicializado correctamente con almacenamiento en memoria.")

    @property
    def clientes(self) -> List[Cliente]:
        return self._clientes

    @property
    def servicios(self) -> List[Servicio]:
        return self._servicios

    @property
    def reservas(self) -> List[Reserva]:
        return self._reservas

    # --- Gestión de Clientes ---
    def registrar_cliente(self, identificacion: str, nombre_completo: str, correo: str, telefono: str) -> Cliente:
        logger.info(f"Intentando registrar cliente con identificación: {identificacion}...")

        if any(c.identificacion == str(identificacion).strip() for c in self._clientes):
            mensaje = f"Ya existe un cliente registrado con la identificación '{identificacion}'."
            logger.warning(f"Rechazo de registro: {mensaje}")
            raise RegistroDuplicadoError(mensaje)

        nuevo_cliente = Cliente(
            identificacion=identificacion,
            nombre_completo=nombre_completo,
            correo=correo,
            telefono=telefono
        )
        self._clientes.append(nuevo_cliente)
        return nuevo_cliente

    def buscar_cliente(self, identificacion: str) -> Cliente:
        identificacion_limpia = str(identificacion).strip()
        for cliente in self._clientes:
            if cliente.identificacion == identificacion_limpia:
                return cliente
        logger.warning(f"Búsqueda infructuosa: Cliente con identificación '{identificacion}' no encontrado.")
        raise EntidadNoEncontradaError(f"No se encontró ningún cliente con la identificación '{identificacion}'.")

    # --- Gestión de Servicios ---
    def registrar_servicio(self, servicio: Servicio) -> Servicio:
        if not isinstance(servicio, Servicio):
            raise DatoInvalidoError("El servicio a registrar debe ser una instancia derivada de Servicio.")

        if any(s.id_servicio == servicio.id_servicio for s in self._servicios):
            mensaje = f"Ya existe un servicio registrado con el código '{servicio.id_servicio}'."
            logger.warning(f"Rechazo de servicio duplicado: {mensaje}")
            raise RegistroDuplicadoError(mensaje)

        self._servicios.append(servicio)
        logger.info(f"Servicio registrado exitosamente: {servicio.id_servicio} - {servicio.nombre_servicio}")
        return servicio

    def buscar_servicio(self, id_servicio: str) -> Servicio:
        id_limpio = str(id_servicio).strip().upper()
        for s in self._servicios:
            if s.id_servicio == id_limpio:
                return s
        logger.warning(f"Búsqueda infructuosa: Servicio '{id_servicio}' no encontrado.")
        raise EntidadNoEncontradaError(f"No se encontró ningún servicio con el código '{id_servicio}'.")

    # --- Gestión de Reservas ---
    def crear_reserva(
        self,
        codigo_reserva: str,
        identificacion_cliente: str,
        id_servicio: str,
        duracion_horas: float,
        observaciones: str = ""
    ) -> Reserva:
        logger.info(f"Solicitud de creación de reserva: {codigo_reserva}...")

        if any(r.codigo_reserva == str(codigo_reserva).strip().upper() for r in self._reservas):
            mensaje = f"Ya existe una reserva con el código '{codigo_reserva}'."
            logger.warning(f"Rechazo de reserva duplicada: {mensaje}")
            raise RegistroDuplicadoError(mensaje)

        cliente = self.buscar_cliente(identificacion_cliente)
        servicio = self.buscar_servicio(id_servicio)

        nueva_reserva = Reserva(
            codigo_reserva=codigo_reserva,
            cliente=cliente,
            servicio=servicio,
            duracion_horas=duracion_horas,
            observaciones=observaciones
        )
        self._reservas.append(nueva_reserva)
        return nueva_reserva

    def buscar_reserva(self, codigo_reserva: str) -> Reserva:
        codigo_limpio = str(codigo_reserva).strip().upper()
        for r in self._reservas:
            if r.codigo_reserva == codigo_limpio:
                return r
        logger.warning(f"Búsqueda infructuosa: Reserva '{codigo_reserva}' no encontrada.")
        raise EntidadNoEncontradaError(f"No se encontró ninguna reserva con el código '{codigo_reserva}'.")

    def confirmar_reserva(self, codigo_reserva: str) -> None:
        reserva = self.buscar_reserva(codigo_reserva)
        reserva.confirmar()

    def cancelar_reserva(self, codigo_reserva: str, motivo: str = "Cancelación administrativa") -> None:
        reserva = self.buscar_reserva(codigo_reserva)
        reserva.cancelar(motivo=motivo)

    def procesar_reserva(
        self,
        codigo_reserva: str,
        porcentaje_impuesto: float = 0.19,
        porcentaje_descuento: float = 0.0,
        seguro_adicional: float = 0.0,
        cupon: Optional[str] = None,
        **kwargs
    ) -> Dict[str, float]:
        reserva = self.buscar_reserva(codigo_reserva)
        return reserva.procesar(
            porcentaje_impuesto=porcentaje_impuesto,
            porcentaje_descuento=porcentaje_descuento,
            seguro_adicional=seguro_adicional,
            cupon=cupon,
            **kwargs
        )

    # --- Consultas y Reportes ---
    def listar_clientes(self) -> List[str]:
        return [c.obtener_detalle() for c in self._clientes]

    def listar_servicios(self) -> List[str]:
        return [s.describir_servicio() for s in self._servicios]

    def listar_reservas(self) -> List[str]:
        return [r.obtener_detalle() for r in self._reservas]

    def generar_reporte_financiero(self) -> Dict[str, Any]:
        total_facturado = sum(r.costo_total for r in self._reservas if r.estado == EstadoReserva.FINALIZADA)
        conteo_estados = {estado.value: 0 for estado in EstadoReserva}
        for r in self._reservas:
            conteo_estados[r.estado.value] += 1

        return {
            "total_clientes": len(self._clientes),
            "total_servicios": len(self._servicios),
            "total_reservas": len(self._reservas),
            "reservas_por_estado": conteo_estados,
            "total_facturado_cop": round(total_facturado, 2),
        }


# ==================================================================================================
# 11. BATERÍA DE SIMULACIÓN DE 12 OPERACIONES (REQUISITO OFICIAL UNAD)
# ==================================================================================================
def ejecutar_simulacion_requerida(sistema: SistemaGestionFJ, stream_salida=None) -> str:
    """
    Ejecuta una batería de al menos 10 operaciones completas (12 en total),
    demostrando que el sistema maneja excepciones avanzadas, registra eventos en el archivo
    de logs (software_fj.log) y continúa su ejecución sin caerse.
    Retorna la salida completa como texto para la interfaz gráfica y consola.
    """
    buffer = io.StringIO()
    separador_doble = "=" * 90
    separador_simple = "-" * 90

    def escribir(linea: str = ""):
        buffer.write(linea + "\n")
        if stream_salida:
            stream_salida.write(linea + "\n")
        else:
            print(linea)

    escribir(f"\n{separador_doble}")
    escribir("   SOFTWARE FJ - SIMULACIÓN OFICIAL DE OPERACIONES (FASE 4 - UNAD 213023)")
    escribir("   Demostración de POO rigurosa, excepciones avanzadas y tolerancia a fallos")
    escribir(f"{separador_doble}\n")

    # OPERACIÓN 1 [VÁLIDA]
    escribir("[OPERACIÓN 1/12] [VÁLIDA] Registro de Cliente Válido (Datos correctos y formato estricto)")
    try:
        cli1 = sistema.registrar_cliente(
            identificacion="1098765432",
            nombre_completo="Pablo Andrés Plata Marín",
            correo="pablo.plata@unad.edu.co",
            telefono="3158901234"
        )
        escribir(f"  --> ÉXITO: {cli1.obtener_detalle()}")
    except SoftwareFJError as e:
        escribir(f"  --> ERROR NO ESPERADO: {e}")
    escribir(separador_simple)

    # OPERACIÓN 2 [INVÁLIDA]
    escribir("[OPERACIÓN 2/12] [INVÁLIDA] Intento de Registro de Cliente con Correo y Cédula Inválidos")
    escribir("  (Se espera captura controlada de DatoInvalidoError con encadenamiento y registro en log)")
    try:
        sistema.registrar_cliente(
            identificacion="1098765ABC",
            nombre_completo="Carlos Andrés López",
            correo="correo_invalido_sin_arroba",
            telefono="300123"
        )
        escribir("  --> FALLO: El sistema permitió el registro erróneo.")
    except DatoInvalidoError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir("  --> Evento registrado en 'software_fj.log'. La aplicación sigue activa y estable.")
    escribir(separador_simple)

    # OPERACIÓN 3 [INVÁLIDA]
    escribir("[OPERACIÓN 3/12] [INVÁLIDA] Intento de Registro de Cliente Duplicado (Mismo Documento)")
    escribir("  (Se espera captura de RegistroDuplicadoError)")
    try:
        sistema.registrar_cliente(
            identificacion="1098765432",
            nombre_completo="Homónimo de Prueba",
            correo="otro.correo@dominio.com",
            telefono="3119876543"
        )
        escribir("  --> FALLO: Se permitió duplicar cliente.")
    except RegistroDuplicadoError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir("  --> Se rechazó el duplicado protegiendo la integridad en memoria.")
    escribir(separador_simple)

    # OPERACIÓN 4 [VÁLIDA]
    escribir("[OPERACIÓN 4/12] [VÁLIDA] Registro de los Tres (3) Servicios Especializados")
    try:
        sala = ReservaSala(
            id_servicio="SAL-101",
            nombre_servicio="Sala Ejecutiva Innovación",
            tarifa_base_hora=45000.0,
            capacidad_personas=20,
            tiene_proyector=True,
            tiene_aire_acondicionado=True
        )
        sistema.registrar_servicio(sala)

        laptop = AlquilerEquipo(
            id_servicio="EQP-201",
            nombre_servicio="Workstation Móvil Dell Precision",
            tarifa_base_hora=25000.0,
            marca_modelo="Dell Precision 5570 i7 32GB",
            tipo_equipo="Computación de Alto Rendimiento",
            deposito_garantia=300000.0
        )
        sistema.registrar_servicio(laptop)

        asesoria = AsesoriaEspecializada(
            id_servicio="ASE-301",
            nombre_servicio="Consultoría Arquitectura Cloud AWS",
            tarifa_base_hora=80000.0,
            area_experiencia="Cloud Computing y Microservicios",
            nivel_consultor="SENIOR"
        )
        sistema.registrar_servicio(asesoria)

        escribir("  --> ÉXITO en la creación polimórfica de servicios:")
        escribir(f"      1. {sala.describir_servicio()}")
        escribir(f"      2. {laptop.describir_servicio()}")
        escribir(f"      3. {asesoria.describir_servicio()}")
    except SoftwareFJError as e:
        escribir(f"  --> ERROR NO ESPERADO: {e}")
    escribir(separador_simple)

    # OPERACIÓN 5 [INVÁLIDA]
    escribir("[OPERACIÓN 5/12] [INVÁLIDA] Creación Incorrecta de Servicio (Capacidad negativa o tarifa no numérica)")
    escribir("  (Se espera captura de DatoInvalidoError con encadenamiento de excepciones)")
    try:
        sala_invalida = ReservaSala(
            id_servicio="SAL-ERR",
            nombre_servicio="Sala Fantasma",
            tarifa_base_hora=30000.0,
            capacidad_personas=-10
        )
        sistema.registrar_servicio(sala_invalida)
        escribir("  --> FALLO: Se permitió crear una sala con capacidad negativa.")
    except DatoInvalidoError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir("  --> Encadenamiento y registro de log auditados exitosamente.")
    escribir(separador_simple)

    # OPERACIÓN 6 [VÁLIDA]
    escribir("[OPERACIÓN 6/12] [VÁLIDA] Creación y Confirmación de Reserva de Sala (Cálculo Sobrecargado)")
    try:
        sistema.registrar_cliente(
            identificacion="1012345678",
            nombre_completo="María Fernanda Gómez",
            correo="maria.gomez@empresa.com",
            telefono="3207654321"
        )

        res1 = sistema.crear_reserva(
            codigo_reserva="RES-001",
            identificacion_cliente="1012345678",
            id_servicio="SAL-101",
            duracion_horas=4.0,
            observaciones="Reunión mensual de planeación estratégica"
        )
        escribir(f"  --> Reserva creada: {res1.obtener_detalle()}")

        sistema.confirmar_reserva("RES-001")
        escribir(f"  --> Reserva confirmada: Estado actual = {res1.estado.value}")

        escribir("  --> Invocando método sobrecargado con descuento, IVA y cupón...")
        desglose = sistema.procesar_reserva(
            codigo_reserva="RES-001",
            porcentaje_impuesto=0.19,
            porcentaje_descuento=0.05,
            cupon="ESTUDIANTE"
        )
        escribir("  --> Liquidación financiera exitosa:")
        for clave, valor in desglose.items():
            escribir(f"      * {clave}: ${valor:,.2f}" if isinstance(valor, float) else f"      * {clave}: {valor}")
    except SoftwareFJError as e:
        escribir(f"  --> ERROR NO ESPERADO: {e}")
    escribir(separador_simple)

    # OPERACIÓN 7 [INVÁLIDA]
    escribir("[OPERACIÓN 7/12] [INVÁLIDA] Intento de Creación de Reserva con Duración Negativa (0 o -5 horas)")
    escribir("  (Se espera captura de ReservaInvalidaError)")
    try:
        sistema.crear_reserva(
            codigo_reserva="RES-ERR-DUR",
            identificacion_cliente="1098765432",
            id_servicio="EQP-201",
            duracion_horas=-5.0,
            observaciones="Prueba de fallo por tiempo negativo"
        )
        escribir("  --> FALLO: Se permitió duración negativa.")
    except ReservaInvalidaError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir("  --> La reserva fue abortada antes de alterar las listas internas.")
    escribir(separador_simple)

    # OPERACIÓN 8 [INVÁLIDA]
    escribir("[OPERACIÓN 8/12] [INVÁLIDA] Intento de Reserva sobre un Servicio Inactivo / Fuera de Servicio")
    escribir("  (Se espera captura de ServicioNoDisponibleError)")
    try:
        laptop_ref = sistema.buscar_servicio("EQP-201")
        laptop_ref.activo = False
        escribir(f"  [Info] El servicio {laptop_ref.id_servicio} fue puesto en mantenimiento (activo=False).")

        sistema.crear_reserva(
            codigo_reserva="RES-ERR-INACT",
            identificacion_cliente="1098765432",
            id_servicio="EQP-201",
            duracion_horas=3.0
        )
        escribir("  --> FALLO: Se permitió reservar un servicio inactivo.")
    except ServicioNoDisponibleError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir("  --> Se restaura el servicio para pruebas posteriores.")
    finally:
        laptop_ref.activo = True
    escribir(separador_simple)

    # OPERACIÓN 9 [VÁLIDA]
    escribir("[OPERACIÓN 9/12] [VÁLIDA] Flujo Completo de Asesoría Especializada (try/except/else/finally)")
    try:
        res2 = sistema.crear_reserva(
            codigo_reserva="RES-002",
            identificacion_cliente="1098765432",
            id_servicio="ASE-301",
            duracion_horas=5.0,
            observaciones="Diagnóstico de infraestructura cloud y optimización de costos"
        )
        sistema.confirmar_reserva("RES-002")

        factura_asesoria = sistema.procesar_reserva(
            codigo_reserva="RES-002",
            porcentaje_impuesto=0.19,
            porcentaje_descuento=0.10,
            incluye_informe=True
        )
        escribir(f"  --> Asesoría procesada exitosamente: {res2.obtener_detalle()}")
        escribir(f"  --> Total liquidado: ${factura_asesoria['total_final']:,.2f} COP")
    except SoftwareFJError as e:
        escribir(f"  --> ERROR NO ESPERADO: {e}")
    escribir(separador_simple)

    # OPERACIÓN 10 [INVÁLIDA]
    escribir("[OPERACIÓN 10/12] [INVÁLIDA] Transición Ilegal: Cancelar Dos Veces una Misma Reserva")
    escribir("  (Se espera captura de OperacionNoPermitidaError)")
    try:
        res3 = sistema.crear_reserva(
            codigo_reserva="RES-003",
            identificacion_cliente="1012345678",
            id_servicio="SAL-101",
            duracion_horas=2.0
        )
        sistema.cancelar_reserva("RES-003", motivo="Cliente reprogramó evento")
        escribir(f"  [Info] Reserva RES-003 cancelada por primera vez. Estado = {res3.estado.value}")

        escribir("  --> Intentando segunda cancelación redundante...")
        sistema.cancelar_reserva("RES-003", motivo="Intento reiterado de cancelación")
        escribir("  --> FALLO: Se permitió cancelar una reserva ya cancelada.")
    except OperacionNoPermitidaError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir("  --> Máquina de estados íntegra. Violación de flujo prevenida y registrada.")
    escribir(separador_simple)

    # OPERACIÓN 11 [INVÁLIDA]
    escribir("[OPERACIÓN 11/12] [INVÁLIDA] Intento de Cálculo Inconsistente (Descuento del 180% con encadenamiento)")
    escribir("  (Se espera captura de CalculoInconsistenteError)")
    try:
        sistema.crear_reserva(
            codigo_reserva="RES-004",
            identificacion_cliente="1098765432",
            id_servicio="ASE-301",
            duracion_horas=3.0
        )
        sistema.confirmar_reserva("RES-004")

        sistema.procesar_reserva(
            codigo_reserva="RES-004",
            porcentaje_descuento=1.8
        )
        escribir("  --> FALLO: Se permitió un descuento superior al 100%.")
    except CalculoInconsistenteError as e:
        escribir(f"  --> CONTROLADO CORRECTAMENTE: Excepción capturada -> {e}")
        escribir(f"  --> Causa raíz encadenada: {e.__cause__}")
        escribir("  --> Registro de auditoría guardado en el archivo de logs.")
    escribir(separador_simple)

    # OPERACIÓN 12 [VÁLIDA]
    escribir("[OPERACIÓN 12/12] [VÁLIDA] Ciclo Completo de Alquiler de Equipo con Depósito y Seguro de Daños")
    try:
        res5 = sistema.crear_reserva(
            codigo_reserva="RES-005",
            identificacion_cliente="1012345678",
            id_servicio="EQP-201",
            duracion_horas=8.0,
            observaciones="Alquiler para jornada de desarrollo intensivo (Hackathon)"
        )
        sistema.confirmar_reserva("RES-005")

        factura_equipo = sistema.procesar_reserva(
            codigo_reserva="RES-005",
            porcentaje_impuesto=0.19,
            seguro_adicional=15000.0,
            incluir_seguro=True
        )
        escribir(f"  --> Alquiler procesado exitosamente: {res5.obtener_detalle()}")
        laptop_obj = sistema.buscar_servicio("EQP-201")
        if isinstance(laptop_obj, AlquilerEquipo):
            escribir(f"  --> Depósito en garantía requerido: ${laptop_obj.deposito_garantia:,.2f} COP")
        escribir(f"  --> Total facturado del servicio: ${factura_equipo['total_final']:,.2f} COP")
    except SoftwareFJError as e:
        escribir(f"  --> ERROR NO ESPERADO: {e}")
    escribir(separador_simple)

    # BALANCE FINAL
    reporte = sistema.generar_reporte_financiero()
    escribir(f"\n{separador_doble}")
    escribir("                  INFORME GENERAL CONSOLIDADO DEL SISTEMA SOFTWARE FJ")
    escribir(f"{separador_doble}")
    escribir(f"  * Total Clientes en Memoria:  {reporte['total_clientes']}")
    escribir(f"  * Total Servicios Activos:    {reporte['total_servicios']}")
    escribir(f"  * Total Reservas Gestionadas: {reporte['total_reservas']}")
    escribir("  * Distribución por Estados:")
    for est, cant in reporte["reservas_por_estado"].items():
        escribir(f"      - {est}: {cant} reserva(s)")
    escribir(f"  * Total Facturado Liquidado:  ${reporte['total_facturado_cop']:,.2f} COP")
    escribir(f"  * Ubicación Archivo de Logs:  {ARCHIVO_LOG}")
    escribir(f"  * Estado de la Aplicación:    ESTABLE Y EN OPERACIÓN (CERO CAÍDAS)")
    escribir(f"{separador_doble}\n")

    return buffer.getvalue()


# ==================================================================================================
# 12. INTERFAZ GRÁFICA DE USUARIO CON TKINTER (PALETA CAFÉ MEDIO Y BLANCO HUESO)
# ==================================================================================================

# --- PALETA CROMÁTICA: CAFÉ MEDIO Y BLANCO HUESO ---
COLOR_CAFE_OSCURO   = "#4E3629"   # Café oscuro elegante para textos y énfasis
COLOR_CAFE_MEDIO    = "#7B5238"   # Café medio cálido (color corporativo primario)
COLOR_CAFE_HOVER    = "#8D6246"   # Café medio-claro para interacción y foco
COLOR_CAFE_SUAVE    = "#D8CAB8"   # Café con leche claro / beige para bordes y encabezados de tabla
COLOR_BLANCO_HUESO  = "#F7F4EE"   # Blanco hueso auténtico para el fondo general
COLOR_HUESO_TARJETA = "#FDFBF7"   # Blanco hueso marfil claro para paneles, tarjetas y formularios
COLOR_HUESO_BORDE   = "#E5DEC9"   # Tono hueso para separadores y marcos
COLOR_TEXTO_OSCURO  = "#2E2018"   # Texto café muy oscuro (máximo contraste y legibilidad)
COLOR_TEXTO_CLARO   = "#FAF6EE"   # Texto blanco hueso para botones de fondo café
COLOR_ACCION_VERDE  = "#5C7548"   # Verde olivo tierra para confirmaciones (armónico con café)
COLOR_ACCION_ROJO   = "#A34735"   # Terracota / teja para cancelaciones (armónico con café)
COLOR_ACCION_AMBAR  = "#B87333"   # Cobre / ámbar cálido para liquidación financiera
COLOR_TERMINAL_BG   = "#241A15"   # Café moca muy oscuro para la consola de simulación y logs
COLOR_TERMINAL_FG   = "#F5EBE1"   # Texto blanco hueso cálido en consola terminal


class VentanaLogin(tk.Tk):
    """
    Ventana de inicio de sesión con validaciones de credenciales, control de intentos,
    registro en logs y acceso a la interfaz principal de Software FJ.
    Diseñada con paleta de café medio y blanco hueso.
    """

    def __init__(self, sistema: SistemaGestionFJ):
        super().__init__()
        self.sistema = sistema
        self.auth = GestorAutenticacion(max_intentos=3)

        self.title("Software FJ - Inicio de Sesión (UNAD 213023)")
        self.geometry("470x530")
        self.resizable(False, False)
        self.configure(bg=COLOR_BLANCO_HUESO)

        self._centrar_ventana(470, 530)
        self._construir_interfaz()

    def _centrar_ventana(self, ancho: int, alto: int) -> None:
        self.update_idletasks()
        pantalla_ancho = self.winfo_screenwidth()
        pantalla_alto = self.winfo_screenheight()
        x = (pantalla_ancho // 2) - (ancho // 2)
        y = (pantalla_alto // 2) - (alto // 2)
        self.geometry(f"{ancho}x{alto}+{x}+{y}")

    def _construir_interfaz(self) -> None:
        # Encabezado corporativo en café medio
        frame_encabezado = tk.Frame(self, bg=COLOR_CAFE_MEDIO, pady=16)
        frame_encabezado.pack(fill="x")

        lbl_logo = tk.Label(
            frame_encabezado,
            text="🏢 SOFTWARE FJ",
            font=("Segoe UI", 20, "bold"),
            fg=COLOR_TEXTO_CLARO,
            bg=COLOR_CAFE_MEDIO
        )
        lbl_logo.pack()

        lbl_sub = tk.Label(
            frame_encabezado,
            text="Sistema Integral de Clientes, Servicios y Reservas\nCurso: Programación (213023) - Fase 4 UNAD",
            font=("Segoe UI", 9),
            fg=COLOR_CAFE_SUAVE,
            bg=COLOR_CAFE_MEDIO,
            justify="center"
        )
        lbl_sub.pack(pady=4)

        # Tarjeta central de formulario en blanco hueso
        frame_tarjeta = tk.Frame(
            self,
            bg=COLOR_HUESO_TARJETA,
            bd=1,
            relief="solid",
            highlightthickness=1,
            highlightbackground=COLOR_HUESO_BORDE
        )
        frame_tarjeta.pack(padx=28, pady=16, fill="both", expand=True)

        lbl_titulo_login = tk.Label(
            frame_tarjeta,
            text="Autenticación de Acceso",
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_CAFE_OSCURO,
            bg=COLOR_HUESO_TARJETA
        )
        lbl_titulo_login.pack(pady=(15, 10))

        # Campo Usuario
        lbl_usuario = tk.Label(
            frame_tarjeta,
            text="Nombre de Usuario:",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_TEXTO_OSCURO,
            bg=COLOR_HUESO_TARJETA
        )
        lbl_usuario.pack(anchor="w", padx=25, pady=(5, 2))

        self.txt_usuario = ttk.Entry(frame_tarjeta, font=("Segoe UI", 10))
        self.txt_usuario.pack(fill="x", padx=25, ipady=3)
        self.txt_usuario.insert(0, "admin")

        # Campo Contraseña
        lbl_clave = tk.Label(
            frame_tarjeta,
            text="Contraseña:",
            font=("Segoe UI", 9, "bold"),
            fg=COLOR_TEXTO_OSCURO,
            bg=COLOR_HUESO_TARJETA
        )
        lbl_clave.pack(anchor="w", padx=25, pady=(10, 2))

        self.txt_clave = ttk.Entry(frame_tarjeta, font=("Segoe UI", 10), show="•")
        self.txt_clave.pack(fill="x", padx=25, ipady=3)
        self.txt_clave.insert(0, "admin123")

        # Vincular Enter para ingreso rápido
        self.txt_clave.bind("<Return>", lambda event: self._intentar_login())

        # Etiqueta de credenciales de prueba
        lbl_info = tk.Label(
            frame_tarjeta,
            text="💡 Credenciales sugeridas para prueba:\nadmin / admin123   |   programacion / programacion",
            font=("Segoe UI", 8),
            fg=COLOR_CAFE_OSCURO,
            bg="#EFEAE0",
            relief="solid",
            bd=1,
            padx=8,
            pady=4
        )
        lbl_info.pack(padx=25, pady=(12, 12), fill="x")

        # Botón Ingresar en café medio con texto blanco hueso
        btn_login = tk.Button(
            frame_tarjeta,
            text="INGRESAR AL SISTEMA",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            relief="flat",
            cursor="hand2",
            command=self._intentar_login
        )
        btn_login.pack(fill="x", padx=25, ipady=6, pady=(0, 6))

        # Botón para ejecutar Simulación directa en consola
        btn_simulacion = tk.Button(
            frame_tarjeta,
            text="Ejecutar Simulación 12 Operaciones en Consola",
            font=("Segoe UI", 8),
            bg="#ECE4D8",
            fg=COLOR_CAFE_OSCURO,
            activebackground="#DFD5C6",
            activeforeground=COLOR_CAFE_OSCURO,
            relief="flat",
            cursor="hand2",
            command=self._ejecutar_simulacion_directa
        )
        btn_simulacion.pack(fill="x", padx=25, ipady=3)

    def _intentar_login(self) -> None:
        usuario = self.txt_usuario.get()
        clave = self.txt_clave.get()

        try:
            self.auth.autenticar(usuario, clave)
            messagebox.showinfo(
                "Acceso Autorizado",
                f"¡Bienvenido al Sistema de Software FJ, {self.auth.usuario_actual}!\n"
                "Iniciando entorno gráfico principal..."
            )
            logger.info(f"Sesión iniciada correctamente por {self.auth.usuario_actual}.")

            self.destroy()
            app_principal = VentanaPrincipalGUI(self.sistema, self.auth.usuario_actual or "admin")
            app_principal.mainloop()

        except ParametroFaltanteError as err:
            logger.warning(f"Intento de login con campos faltantes: {err}")
            messagebox.showwarning("Campos Requeridos", str(err))

        except CredencialesInvalidasError as err:
            logger.warning(f"Intento de login fallido: {err}")
            messagebox.showerror("Error de Credenciales", str(err))
            self.txt_clave.delete(0, tk.END)

        except OperacionNoPermitidaError as err:
            logger.critical(f"Bloqueo de seguridad activado: {err}")
            messagebox.showerror("Sistema Bloqueado", str(err))
            self.txt_usuario.config(state="disabled")
            self.txt_clave.config(state="disabled")

        except Exception as ex:
            logger.exception("Error imprevisto en login:")
            messagebox.showerror("Error Inesperado", f"Ha ocurrido un error en la autenticación: {ex}")

    def _ejecutar_simulacion_directa(self) -> None:
        try:
            print("\n>>> INICIANDO SIMULACIÓN DE OPERACIONES DESDE PANTALLA DE ACCESO <<<")
            resultado = ejecutar_simulacion_requerida(self.sistema)
            messagebox.showinfo(
                "Simulación Exitosa",
                "Las 12 operaciones oficiales se han ejecutado satisfactoriamente.\n"
                "Revise la salida en la consola de comandos y en 'software_fj.log'."
            )
        except Exception as err:
            messagebox.showerror("Error en Simulación", str(err))


class VentanaPrincipalGUI(tk.Tk):
    """
    Ventana principal con sistema de pestañas (Notebook) para la administración
    completa de Clientes, Servicios, Reservas, Simulación de Operaciones y Visor de Logs.
    Estilizada con los colores base Café Medio y Blanco Hueso.
    """

    def __init__(self, sistema: SistemaGestionFJ, usuario: str):
        super().__init__()
        self.sistema = sistema
        self.usuario = usuario

        self.title(f"Software FJ - Sistema Integral de Gestión | Usuario: {self.usuario}")
        self.geometry("990x690")
        self.minsize(920, 620)
        self.configure(bg=COLOR_BLANCO_HUESO)

        self._configurar_estilos()
        self._construir_interfaz_principal()
        self._cargar_datos_iniciales_si_vacio()
        self._refrescar_todas_las_tablas()

    def _configurar_estilos(self) -> None:
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Configuración estética del Notebook (Pestañas)
        self.style.configure("TNotebook", background=COLOR_BLANCO_HUESO)
        self.style.configure(
            "TNotebook.Tab",
            background=COLOR_HUESO_TARJETA,
            foreground=COLOR_CAFE_OSCURO,
            font=("Segoe UI", 9, "bold"),
            padding=[14, 6]
        )
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", COLOR_CAFE_MEDIO), ("active", COLOR_CAFE_HOVER)],
            foreground=[("selected", COLOR_TEXTO_CLARO), ("active", COLOR_TEXTO_CLARO)]
        )

        # Configuración estética de Treeview (Tablas de datos)
        self.style.configure(
            "Treeview",
            font=("Segoe UI", 9),
            rowheight=26,
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground=COLOR_TEXTO_OSCURO
        )
        self.style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold"),
            background=COLOR_CAFE_SUAVE,
            foreground=COLOR_CAFE_OSCURO,
            relief="flat"
        )
        self.style.map(
            "Treeview",
            background=[("selected", COLOR_CAFE_MEDIO)],
            foreground=[("selected", COLOR_TEXTO_CLARO)]
        )

    def _construir_interfaz_principal(self) -> None:
        # Barra superior con información en café medio
        frame_top = tk.Frame(self, bg=COLOR_CAFE_MEDIO, height=60)
        frame_top.pack(fill="x")

        lbl_brand = tk.Label(
            frame_top,
            text="🏢 SOFTWARE FJ  |  Gestión Integral de Clientes, Servicios y Reservas",
            font=("Segoe UI", 12, "bold"),
            fg=COLOR_TEXTO_CLARO,
            bg=COLOR_CAFE_MEDIO
        )
        lbl_brand.pack(side="left", padx=20, pady=12)

        lbl_user = tk.Label(
            frame_top,
            text=f"👤 Sesión: {self.usuario}  |  UNAD ECBTI 213023",
            font=("Segoe UI", 9),
            fg=COLOR_CAFE_SUAVE,
            bg=COLOR_CAFE_MEDIO
        )
        lbl_user.pack(side="right", padx=20, pady=12)

        # Contenedor con pestañas (Notebook)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=15)

        # Creación de cada pestaña
        self.tab_clientes = ttk.Frame(self.notebook)
        self.tab_servicios = ttk.Frame(self.notebook)
        self.tab_reservas = ttk.Frame(self.notebook)
        self.tab_simulacion = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_clientes, text="  👥 Clientes  ")
        self.notebook.add(self.tab_servicios, text="  💼 Catálogo de Servicios  ")
        self.notebook.add(self.tab_reservas, text="  📅 Gestión de Reservas  ")
        self.notebook.add(self.tab_simulacion, text="  🧪 Simulación 12 Operaciones  ")
        self.notebook.add(self.tab_logs, text="  📄 Auditoría / Logs  ")

        # Construir contenido de cada pestaña
        self._construir_tab_clientes()
        self._construir_tab_servicios()
        self._construir_tab_reservas()
        self._construir_tab_simulacion()
        self._construir_tab_logs()

    # ----------------------------------------------------------------------------------------------
    # PESTAÑA 1: GESTIÓN DE CLIENTES
    # ----------------------------------------------------------------------------------------------
    def _construir_tab_clientes(self) -> None:
        frame_form = tk.LabelFrame(
            self.tab_clientes,
            text=" Registrar Nuevo Cliente ",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_HUESO_TARJETA,
            fg=COLOR_CAFE_OSCURO,
            bd=1,
            relief="solid",
            padx=12,
            pady=10
        )
        frame_form.pack(fill="x", padx=10, pady=10)

        # Campos
        tk.Label(frame_form, text="Identificación (6-12 dígitos):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.ent_cli_id = ttk.Entry(frame_form, width=22)
        self.ent_cli_id.grid(row=0, column=1, padx=5, pady=4)

        tk.Label(frame_form, text="Nombre Completo:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=0, column=2, sticky="w", padx=5, pady=4)
        self.ent_cli_nombre = ttk.Entry(frame_form, width=32)
        self.ent_cli_nombre.grid(row=0, column=3, padx=5, pady=4)

        tk.Label(frame_form, text="Correo Electrónico:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=0, sticky="w", padx=5, pady=4)
        self.ent_cli_correo = ttk.Entry(frame_form, width=22)
        self.ent_cli_correo.grid(row=1, column=1, padx=5, pady=4)

        tk.Label(frame_form, text="Teléfono Móvil (10 dígitos):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=2, sticky="w", padx=5, pady=4)
        self.ent_cli_tel = ttk.Entry(frame_form, width=32)
        self.ent_cli_tel.grid(row=1, column=3, padx=5, pady=4)

        btn_guardar_cli = tk.Button(
            frame_form,
            text="✔ Registrar Cliente",
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_registrar_cliente
        )
        btn_guardar_cli.grid(row=0, column=4, rowspan=2, padx=15, pady=4, ipady=8)

        # Tabla de Clientes
        frame_tabla = tk.LabelFrame(
            self.tab_clientes,
            text=" Clientes Registrados en Memoria ",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_HUESO_TARJETA,
            fg=COLOR_CAFE_OSCURO,
            bd=1,
            relief="solid",
            padx=10,
            pady=10
        )
        frame_tabla.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("id", "nombre", "correo", "telefono", "fecha", "estado")
        self.tree_clientes = ttk.Treeview(frame_tabla, columns=cols, show="headings", selectmode="browse")
        self.tree_clientes.heading("id", text="Identificación (ID)")
        self.tree_clientes.heading("nombre", text="Nombre Completo")
        self.tree_clientes.heading("correo", text="Correo Electrónico")
        self.tree_clientes.heading("telefono", text="Teléfono")
        self.tree_clientes.heading("fecha", text="Fecha Registro")
        self.tree_clientes.heading("estado", text="Estado")

        self.tree_clientes.column("id", width=110, anchor="center")
        self.tree_clientes.column("nombre", width=220)
        self.tree_clientes.column("correo", width=210)
        self.tree_clientes.column("telefono", width=110, anchor="center")
        self.tree_clientes.column("fecha", width=140, anchor="center")
        self.tree_clientes.column("estado", width=90, anchor="center")

        scroll_cli = ttk.Scrollbar(frame_tabla, orient="vertical", command=self.tree_clientes.yview)
        self.tree_clientes.configure(yscrollcommand=scroll_cli.set)

        self.tree_clientes.pack(side="left", fill="both", expand=True)
        scroll_cli.pack(side="right", fill="y")

    def _gui_registrar_cliente(self) -> None:
        doc = self.ent_cli_id.get().strip()
        nom = self.ent_cli_nombre.get().strip()
        cor = self.ent_cli_correo.get().strip()
        tel = self.ent_cli_tel.get().strip()

        try:
            cli = self.sistema.registrar_cliente(doc, nom, cor, tel)
            messagebox.showinfo("Cliente Registrado", f"Cliente {cli.nombre_completo} registrado exitosamente.")
            self.ent_cli_id.delete(0, tk.END)
            self.ent_cli_nombre.delete(0, tk.END)
            self.ent_cli_correo.delete(0, tk.END)
            self.ent_cli_tel.delete(0, tk.END)
            self._refrescar_tabla_clientes()
            self._actualizar_combos_reserva()
        except SoftwareFJError as err:
            logger.warning(f"Error de validación al registrar cliente vía GUI: {err}")
            messagebox.showerror("Error al Registrar Cliente", str(err))

    def _refrescar_tabla_clientes(self) -> None:
        for item in self.tree_clientes.get_children():
            self.tree_clientes.delete(item)

        for c in self.sistema.clientes:
            est = "ACTIVO" if c.activo else "INACTIVO"
            fecha_str = c.fecha_registro.strftime("%Y-%m-%d %H:%M")
            self.tree_clientes.insert(
                "",
                "end",
                values=(c.identificacion, c.nombre_completo, c.correo, c.telefono, fecha_str, est)
            )

    # ----------------------------------------------------------------------------------------------
    # PESTAÑA 2: CATÁLOGO DE SERVICIOS
    # ----------------------------------------------------------------------------------------------
    def _construir_tab_servicios(self) -> None:
        frame_form = tk.LabelFrame(
            self.tab_servicios,
            text=" Registrar Nuevo Servicio Especializado ",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_HUESO_TARJETA,
            fg=COLOR_CAFE_OSCURO,
            bd=1,
            relief="solid",
            padx=12,
            pady=10
        )
        frame_form.pack(fill="x", padx=10, pady=10)

        # Selector de Tipo
        tk.Label(frame_form, text="Tipo de Servicio:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO, font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.combo_tipo_srv = ttk.Combobox(frame_form, values=["Reserva de Sala", "Alquiler de Equipo", "Asesoría Especializada"], state="readonly", width=22)
        self.combo_tipo_srv.set("Reserva de Sala")
        self.combo_tipo_srv.grid(row=0, column=1, padx=5, pady=4)
        self.combo_tipo_srv.bind("<<ComboboxSelected>>", self._actualizar_campos_especificos_servicio)

        tk.Label(frame_form, text="Código Único (ID):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=0, column=2, sticky="w", padx=5, pady=4)
        self.ent_srv_id = ttk.Entry(frame_form, width=16)
        self.ent_srv_id.grid(row=0, column=3, padx=5, pady=4)

        tk.Label(frame_form, text="Nombre del Servicio:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=0, sticky="w", padx=5, pady=4)
        self.ent_srv_nombre = ttk.Entry(frame_form, width=24)
        self.ent_srv_nombre.grid(row=1, column=1, padx=5, pady=4)

        tk.Label(frame_form, text="Tarifa Base / Hora ($ COP):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=2, sticky="w", padx=5, pady=4)
        self.ent_srv_tarifa = ttk.Entry(frame_form, width=16)
        self.ent_srv_tarifa.grid(row=1, column=3, padx=5, pady=4)

        # Campos dinámicos
        self.lbl_din1 = tk.Label(frame_form, text="Capacidad Personas:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO)
        self.lbl_din1.grid(row=2, column=0, sticky="w", padx=5, pady=4)
        self.ent_din1 = ttk.Entry(frame_form, width=24)
        self.ent_din1.grid(row=2, column=1, padx=5, pady=4)

        self.lbl_din2 = tk.Label(frame_form, text="Opciones Adicionales:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO)
        self.lbl_din2.grid(row=2, column=2, sticky="w", padx=5, pady=4)
        self.ent_din2 = ttk.Entry(frame_form, width=16)
        self.ent_din2.grid(row=2, column=3, padx=5, pady=4)

        btn_guardar_srv = tk.Button(
            frame_form,
            text="✔ Registrar Servicio",
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_registrar_servicio
        )
        btn_guardar_srv.grid(row=0, column=4, rowspan=3, padx=15, pady=4, ipady=12)

        # Tabla de Servicios
        frame_tabla = tk.LabelFrame(
            self.tab_servicios,
            text=" Servicios Disponibles en Catálogo ",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_HUESO_TARJETA,
            fg=COLOR_CAFE_OSCURO,
            bd=1,
            relief="solid",
            padx=10,
            pady=10
        )
        frame_tabla.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("id", "nombre", "tipo", "tarifa", "detalle", "estado")
        self.tree_servicios = ttk.Treeview(frame_tabla, columns=cols, show="headings", selectmode="browse")
        self.tree_servicios.heading("id", text="ID Servicio")
        self.tree_servicios.heading("nombre", text="Nombre")
        self.tree_servicios.heading("tipo", text="Tipo")
        self.tree_servicios.heading("tarifa", text="Tarifa Base / Hora")
        self.tree_servicios.heading("detalle", text="Detalle Técnico / Alcance")
        self.tree_servicios.heading("estado", text="Estado")

        self.tree_servicios.column("id", width=100, anchor="center")
        self.tree_servicios.column("nombre", width=200)
        self.tree_servicios.column("tipo", width=140, anchor="center")
        self.tree_servicios.column("tarifa", width=130, anchor="e")
        self.tree_servicios.column("detalle", width=280)
        self.tree_servicios.column("estado", width=80, anchor="center")

        scroll_srv = ttk.Scrollbar(frame_tabla, orient="vertical", command=self.tree_servicios.yview)
        self.tree_servicios.configure(yscrollcommand=scroll_srv.set)

        self.tree_servicios.pack(side="left", fill="both", expand=True)
        scroll_srv.pack(side="right", fill="y")

    def _actualizar_campos_especificos_servicio(self, event=None) -> None:
        tipo = self.combo_tipo_srv.get()
        if tipo == "Reserva de Sala":
            self.lbl_din1.config(text="Capacidad de Personas:")
            self.lbl_din2.config(text="Proyector (s/n):")
            self.ent_din1.delete(0, tk.END)
            self.ent_din2.delete(0, tk.END)
            self.ent_din1.insert(0, "15")
            self.ent_din2.insert(0, "s")
        elif tipo == "Alquiler de Equipo":
            self.lbl_din1.config(text="Marca y Modelo:")
            self.lbl_din2.config(text="Depósito Garantía ($):")
            self.ent_din1.delete(0, tk.END)
            self.ent_din2.delete(0, tk.END)
            self.ent_din1.insert(0, "Dell Precision 5570")
            self.ent_din2.insert(0, "200000")
        elif tipo == "Asesoría Especializada":
            self.lbl_din1.config(text="Área de Especialidad:")
            self.lbl_din2.config(text="Nivel (JUNIOR/SENIOR/MASTER):")
            self.ent_din1.delete(0, tk.END)
            self.ent_din2.delete(0, tk.END)
            self.ent_din1.insert(0, "Ciberseguridad")
            self.ent_din2.insert(0, "SENIOR")

    def _gui_registrar_servicio(self) -> None:
        tipo = self.combo_tipo_srv.get()
        cod = self.ent_srv_id.get().strip()
        nom = self.ent_srv_nombre.get().strip()
        tarifa_str = self.ent_srv_tarifa.get().strip()

        try:
            tarifa = float(tarifa_str)
            if tipo == "Reserva de Sala":
                cap = int(self.ent_din1.get().strip())
                proy = self.ent_din2.get().strip().lower() == "s"
                srv = ReservaSala(cod, nom, tarifa, cap, tiene_proyector=proy)
            elif tipo == "Alquiler de Equipo":
                mod = self.ent_din1.get().strip()
                dep = float(self.ent_din2.get().strip())
                srv = AlquilerEquipo(cod, nom, tarifa, marca_modelo=mod, tipo_equipo="Tecnología", deposito_garantia=dep)
            else:
                area = self.ent_din1.get().strip()
                niv = self.ent_din2.get().strip().upper()
                srv = AsesoriaEspecializada(cod, nom, tarifa, area_experiencia=area, nivel_consultor=niv)

            self.sistema.registrar_servicio(srv)
            messagebox.showinfo("Servicio Registrado", f"Servicio {srv.id_servicio} añadido al catálogo.")
            self.ent_srv_id.delete(0, tk.END)
            self.ent_srv_nombre.delete(0, tk.END)
            self.ent_srv_tarifa.delete(0, tk.END)
            self._refrescar_tabla_servicios()
            self._actualizar_combos_reserva()

        except SoftwareFJError as err:
            logger.warning(f"Error al registrar servicio: {err}")
            messagebox.showerror("Error de Servicio", str(err))
        except ValueError as exc:
            logger.error(f"Error numérico: {exc}")
            messagebox.showerror("Dato Numérico Inválido", "Por favor verifique que los campos numéricos contengan valores válidos.")

    def _refrescar_tabla_servicios(self) -> None:
        for item in self.tree_servicios.get_children():
            self.tree_servicios.delete(item)

        for s in self.sistema.servicios:
            tipo_desc = s.__class__.__name__
            est = "ACTIVO" if s.activo else "INACTIVO"
            tarifa_fmt = f"${s.tarifa_base_hora:,.2f}"
            self.tree_servicios.insert(
                "",
                "end",
                values=(s.id_servicio, s.nombre_servicio, tipo_desc, tarifa_fmt, s.describir_servicio(), est)
            )

    # ----------------------------------------------------------------------------------------------
    # PESTAÑA 3: GESTIÓN DE RESERVAS
    # ----------------------------------------------------------------------------------------------
    def _construir_tab_reservas(self) -> None:
        frame_form = tk.LabelFrame(
            self.tab_reservas,
            text=" Crear Nueva Reserva ",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_HUESO_TARJETA,
            fg=COLOR_CAFE_OSCURO,
            bd=1,
            relief="solid",
            padx=12,
            pady=10
        )
        frame_form.pack(fill="x", padx=10, pady=10)

        tk.Label(frame_form, text="Código Reserva:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.ent_res_cod = ttk.Entry(frame_form, width=15)
        self.ent_res_cod.grid(row=0, column=1, padx=5, pady=4)

        tk.Label(frame_form, text="Cliente (ID):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=0, column=2, sticky="w", padx=5, pady=4)
        self.combo_res_cli = ttk.Combobox(frame_form, state="readonly", width=26)
        self.combo_res_cli.grid(row=0, column=3, padx=5, pady=4)

        tk.Label(frame_form, text="Servicio (ID):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=0, sticky="w", padx=5, pady=4)
        self.combo_res_srv = ttk.Combobox(frame_form, state="readonly", width=22)
        self.combo_res_srv.grid(row=1, column=1, padx=5, pady=4)

        tk.Label(frame_form, text="Duración (Horas):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=2, sticky="w", padx=5, pady=4)
        self.ent_res_dur = ttk.Entry(frame_form, width=12)
        self.ent_res_dur.grid(row=1, column=3, padx=5, pady=4, sticky="w")

        tk.Label(frame_form, text="Observaciones:", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=2, column=0, sticky="w", padx=5, pady=4)
        self.ent_res_obs = ttk.Entry(frame_form, width=45)
        self.ent_res_obs.grid(row=2, column=1, columnspan=3, padx=5, pady=4, sticky="w")

        btn_crear_res = tk.Button(
            frame_form,
            text="✔ Crear Reserva",
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_crear_reserva
        )
        btn_crear_res.grid(row=0, column=4, rowspan=3, padx=15, pady=4, ipady=12)

        # Panel de Acciones para Reserva Seleccionada
        frame_acciones = tk.Frame(self.tab_reservas, bg=COLOR_BLANCO_HUESO, pady=5)
        frame_acciones.pack(fill="x", padx=10)

        btn_confirmar = tk.Button(
            frame_acciones,
            text="✔ Confirmar Reserva",
            bg=COLOR_ACCION_VERDE,
            fg=COLOR_TEXTO_CLARO,
            activebackground="#465A36",
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_confirmar_reserva
        )
        btn_confirmar.pack(side="left", padx=5)

        btn_procesar = tk.Button(
            frame_acciones,
            text="💰 Procesar y Liquidar (Cálculo Sobrecargado)",
            bg=COLOR_ACCION_AMBAR,
            fg=COLOR_TEXTO_CLARO,
            activebackground="#965D28",
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_procesar_reserva
        )
        btn_procesar.pack(side="left", padx=5)

        btn_cancelar = tk.Button(
            frame_acciones,
            text="✖ Cancelar Reserva",
            bg=COLOR_ACCION_ROJO,
            fg=COLOR_TEXTO_CLARO,
            activebackground="#823728",
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_cancelar_reserva
        )
        btn_cancelar.pack(side="left", padx=5)

        # Tabla de Reservas
        frame_tabla = tk.LabelFrame(
            self.tab_reservas,
            text=" Reservas Gestionadas ",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_HUESO_TARJETA,
            fg=COLOR_CAFE_OSCURO,
            bd=1,
            relief="solid",
            padx=10,
            pady=10
        )
        frame_tabla.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("codigo", "cliente", "servicio", "horas", "estado", "total", "observaciones")
        self.tree_reservas = ttk.Treeview(frame_tabla, columns=cols, show="headings", selectmode="browse")
        self.tree_reservas.heading("codigo", text="Código")
        self.tree_reservas.heading("cliente", text="Cliente")
        self.tree_reservas.heading("servicio", text="Servicio")
        self.tree_reservas.heading("horas", text="Horas")
        self.tree_reservas.heading("estado", text="Estado")
        self.tree_reservas.heading("total", text="Total Liquidado")
        self.tree_reservas.heading("observaciones", text="Observaciones")

        self.tree_reservas.column("codigo", width=90, anchor="center")
        self.tree_reservas.column("cliente", width=180)
        self.tree_reservas.column("servicio", width=180)
        self.tree_reservas.column("horas", width=70, anchor="center")
        self.tree_reservas.column("estado", width=110, anchor="center")
        self.tree_reservas.column("total", width=130, anchor="e")
        self.tree_reservas.column("observaciones", width=180)

        scroll_res = ttk.Scrollbar(frame_tabla, orient="vertical", command=self.tree_reservas.yview)
        self.tree_reservas.configure(yscrollcommand=scroll_res.set)

        self.tree_reservas.pack(side="left", fill="both", expand=True)
        scroll_res.pack(side="right", fill="y")

    def _actualizar_combos_reserva(self) -> None:
        lista_cli = [f"{c.identificacion} - {c.nombre_completo}" for c in self.sistema.clientes]
        self.combo_res_cli["values"] = lista_cli
        if lista_cli and not self.combo_res_cli.get():
            self.combo_res_cli.set(lista_cli[0])

        lista_srv = [f"{s.id_servicio} - {s.nombre_servicio}" for s in self.sistema.servicios]
        self.combo_res_srv["values"] = lista_srv
        if lista_srv and not self.combo_res_srv.get():
            self.combo_res_srv.set(lista_srv[0])

    def _gui_crear_reserva(self) -> None:
        cod = self.ent_res_cod.get().strip()
        cli_sel = self.combo_res_cli.get()
        srv_sel = self.combo_res_srv.get()
        dur_str = self.ent_res_dur.get().strip()
        obs = self.ent_res_obs.get().strip()

        if not cod:
            messagebox.showwarning("Código Requerido", "Debe ingresar un código para la reserva.")
            return

        if not cli_sel or not srv_sel:
            messagebox.showwarning("Selección Incompleta", "Debe seleccionar un cliente y un servicio registrado.")
            return

        cli_id = cli_sel.split(" - ")[0].strip()
        srv_id = srv_sel.split(" - ")[0].strip()

        try:
            dur = float(dur_str)
            res = self.sistema.crear_reserva(cod, cli_id, srv_id, dur, obs)
            messagebox.showinfo("Reserva Creada", f"Reserva {res.id_entidad} creada en estado {res.estado.value}.")
            self.ent_res_cod.delete(0, tk.END)
            self.ent_res_dur.delete(0, tk.END)
            self.ent_res_obs.delete(0, tk.END)
            self._refrescar_tabla_reservas()
        except SoftwareFJError as err:
            logger.warning(f"Error al crear reserva: {err}")
            messagebox.showerror("Error de Reserva", str(err))
        except ValueError:
            messagebox.showerror("Duración Inválida", "La duración en horas debe ser un número mayor a cero.")

    def _obtener_codigo_reserva_seleccionada(self) -> Optional[str]:
        seleccion = self.tree_reservas.selection()
        if not seleccion:
            messagebox.showwarning("Selección Requerida", "Por favor seleccione una reserva de la tabla.")
            return None
        valores = self.tree_reservas.item(seleccion[0], "values")
        return valores[0]

    def _gui_confirmar_reserva(self) -> None:
        cod = self._obtener_codigo_reserva_seleccionada()
        if not cod:
            return

        try:
            self.sistema.confirmar_reserva(cod)
            messagebox.showinfo("Confirmación Exitosa", f"La reserva {cod} ha pasado a estado CONFIRMADA.")
            self._refrescar_tabla_reservas()
        except SoftwareFJError as err:
            messagebox.showerror("Error al Confirmar", str(err))

    def _gui_cancelar_reserva(self) -> None:
        cod = self._obtener_codigo_reserva_seleccionada()
        if not cod:
            return

        motivo = simpledialog.askstring("Cancelar Reserva", f"Ingrese el motivo de cancelación para {cod}:")
        if motivo is None:
            return

        try:
            self.sistema.cancelar_reserva(cod, motivo=motivo or "Cancelado desde GUI")
            messagebox.showinfo("Cancelación Exitosa", f"La reserva {cod} ha sido CANCELADA.")
            self._refrescar_tabla_reservas()
        except SoftwareFJError as err:
            messagebox.showerror("Error al Cancelar", str(err))

    def _gui_procesar_reserva(self) -> None:
        cod = self._obtener_codigo_reserva_seleccionada()
        if not cod:
            return

        try:
            res = self.sistema.buscar_reserva(cod)
            if res.estado != EstadoReserva.CONFIRMADA:
                raise OperacionNoPermitidaError(
                    f"No se puede procesar la reserva {cod} porque está en estado '{res.estado.value}'. "
                    f"Debe estar en estado CONFIRMADA."
                )

            # Ventana modal de liquidación financiera
            self._abrir_modal_liquidacion(res)

        except SoftwareFJError as err:
            messagebox.showerror("Error de Procesamiento", str(err))

    def _abrir_modal_liquidacion(self, reserva: Reserva) -> None:
        modal = tk.Toplevel(self)
        modal.title(f"Liquidación Financiera - Reserva {reserva.id_entidad}")
        modal.geometry("460x390")
        modal.resizable(False, False)
        modal.configure(bg=COLOR_BLANCO_HUESO)
        modal.transient(self)
        modal.grab_set()

        tk.Label(
            modal,
            text=f"Procesar Reserva: {reserva.id_entidad}",
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_CAFE_OSCURO,
            bg=COLOR_BLANCO_HUESO
        ).pack(pady=(14, 2))

        tk.Label(
            modal,
            text=f"Servicio: {reserva.servicio.nombre_servicio} ({reserva.duracion_horas}h)",
            font=("Segoe UI", 9),
            fg=COLOR_TEXTO_OSCURO,
            bg=COLOR_BLANCO_HUESO
        ).pack(pady=(0, 10))

        frame_campos = tk.Frame(
            modal,
            bg=COLOR_HUESO_TARJETA,
            bd=1,
            relief="solid",
            highlightthickness=1,
            highlightbackground=COLOR_HUESO_BORDE,
            padx=18,
            pady=12
        )
        frame_campos.pack(fill="x", padx=20)

        tk.Label(frame_campos, text="Porcentaje de Descuento (ej. 0.10 para 10%):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=0, column=0, sticky="w", pady=4)
        ent_desc = ttk.Entry(frame_campos, width=15)
        ent_desc.grid(row=0, column=1, pady=4)
        ent_desc.insert(0, "0.0")

        tk.Label(frame_campos, text="Cupón Promocional (ej. FJ2026 / ESTUDIANTE):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=1, column=0, sticky="w", pady=4)
        ent_cupon = ttk.Entry(frame_campos, width=15)
        ent_cupon.grid(row=1, column=1, pady=4)

        tk.Label(frame_campos, text="Seguro Adicional ($ COP):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=2, column=0, sticky="w", pady=4)
        ent_seg = ttk.Entry(frame_campos, width=15)
        ent_seg.grid(row=2, column=1, pady=4)
        ent_seg.insert(0, "0")

        tk.Label(frame_campos, text="Impuesto IVA (0.19 por defecto):", bg=COLOR_HUESO_TARJETA, fg=COLOR_TEXTO_OSCURO).grid(row=3, column=0, sticky="w", pady=4)
        ent_iva = ttk.Entry(frame_campos, width=15)
        ent_iva.grid(row=3, column=1, pady=4)
        ent_iva.insert(0, "0.19")

        def ejecutar_liquidacion():
            try:
                desc = float(ent_desc.get().strip() or 0.0)
                cupon = ent_cupon.get().strip() or None
                seg = float(ent_seg.get().strip() or 0.0)
                iva = float(ent_iva.get().strip() or 0.19)

                factura = self.sistema.procesar_reserva(
                    codigo_reserva=reserva.id_entidad,
                    porcentaje_impuesto=iva,
                    porcentaje_descuento=desc,
                    seguro_adicional=seg,
                    cupon=cupon
                )

                mensaje_exito = (
                    f"¡Reserva {reserva.id_entidad} liquidada con éxito!\n\n"
                    f"Subtotal Base: ${factura['subtotal_base']:,.2f}\n"
                    f"Descuento Aplicado: -${factura['descuento_aplicado']:,.2f}\n"
                    f"Seguro Adicional: +${factura['seguro_adicional']:,.2f}\n"
                    f"IVA (19%): +${factura['impuesto_iva']:,.2f}\n"
                    f"-----------------------------------------\n"
                    f"TOTAL FACTURADO: ${factura['total_final']:,.2f} COP"
                )
                messagebox.showinfo("Liquidación Exitosa", mensaje_exito)
                modal.destroy()
                self._refrescar_tabla_reservas()

            except SoftwareFJError as err:
                messagebox.showerror("Error en Cálculo", str(err))
            except ValueError:
                messagebox.showerror("Error Numérico", "Verifique que los valores numéricos sean correctos.")

        btn_liquidar = tk.Button(
            modal,
            text="APLICAR Y FINALIZAR RESERVA",
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            command=ejecutar_liquidacion
        )
        btn_liquidar.pack(pady=15, ipady=5, padx=30, fill="x")

    def _refrescar_tabla_reservas(self) -> None:
        for item in self.tree_reservas.get_children():
            self.tree_reservas.delete(item)

        for r in self.sistema.reservas:
            costo_txt = f"${r.costo_total:,.2f}" if r.costo_total > 0 else "Sin liquidar"
            self.tree_reservas.insert(
                "",
                "end",
                values=(
                    r.codigo_reserva,
                    r.cliente.nombre_completo,
                    r.servicio.nombre_servicio,
                    r.duracion_horas,
                    r.estado.value,
                    costo_txt,
                    r.observaciones
                )
            )

    # ----------------------------------------------------------------------------------------------
    # PESTAÑA 4: SIMULACIÓN DE 12 OPERACIONES OFICIALES
    # ----------------------------------------------------------------------------------------------
    def _construir_tab_simulacion(self) -> None:
        frame_controles = tk.Frame(self.tab_simulacion, bg=COLOR_BLANCO_HUESO, pady=10)
        frame_controles.pack(fill="x", padx=10)

        btn_run_sim = tk.Button(
            frame_controles,
            text="▶ Ejecutar Batería de Simulación (12 Operaciones Oficiales)",
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_ejecutar_simulacion
        )
        btn_run_sim.pack(side="left", padx=5, ipady=6)

        btn_limpiar_sim = tk.Button(
            frame_controles,
            text="Limpiar Pantalla de Salida",
            bg="#ECE4D8",
            fg=COLOR_CAFE_OSCURO,
            activebackground="#DFD5C6",
            activeforeground=COLOR_CAFE_OSCURO,
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            command=lambda: self.txt_simulacion.delete("1.0", tk.END)
        )
        btn_limpiar_sim.pack(side="left", padx=5, ipady=6)

        # Consola de salida de la simulación en café moca muy oscuro con texto blanco hueso
        self.txt_simulacion = scrolledtext.ScrolledText(
            self.tab_simulacion,
            font=("Consolas", 9),
            bg=COLOR_TERMINAL_BG,
            fg=COLOR_TERMINAL_FG,
            insertbackground=COLOR_TERMINAL_FG,
            wrap="word"
        )
        self.txt_simulacion.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_simulacion.insert(tk.END, "Presione el botón 'Ejecutar Batería de Simulación' para correr las 12 operaciones requeridas.\n")

    def _gui_ejecutar_simulacion(self) -> None:
        self.txt_simulacion.delete("1.0", tk.END)
        self.txt_simulacion.insert(tk.END, "Ejecutando simulación requerida por la guía...\n\n")
        self.update_idletasks()

        salida = ejecutar_simulacion_requerida(self.sistema)
        self.txt_simulacion.insert(tk.END, salida)
        self.txt_simulacion.see(tk.END)

        # Actualizar tablas con los nuevos registros generados
        self._refrescar_todas_las_tablas()
        messagebox.showinfo(
            "Simulación Completada",
            "La simulación de 12 operaciones ha finalizado con éxito.\n"
            "Todos los datos han sido reflejados en memoria y auditados en el log."
        )

    # ----------------------------------------------------------------------------------------------
    # PESTAÑA 5: AUDITORÍA Y ARCHIVO DE LOGS
    # ----------------------------------------------------------------------------------------------
    def _construir_tab_logs(self) -> None:
        frame_controles = tk.Frame(self.tab_logs, bg=COLOR_BLANCO_HUESO, pady=10)
        frame_controles.pack(fill="x", padx=10)

        btn_leer_log = tk.Button(
            frame_controles,
            text="🔄 Actualizar y Leer Log (software_fj.log)",
            bg=COLOR_CAFE_MEDIO,
            fg=COLOR_TEXTO_CLARO,
            activebackground=COLOR_CAFE_OSCURO,
            activeforeground=COLOR_TEXTO_CLARO,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            command=self._gui_leer_archivo_log
        )
        btn_leer_log.pack(side="left", padx=5, ipady=5)

        lbl_ruta_log = tk.Label(
            frame_controles,
            text=f"Ruta: {ARCHIVO_LOG}",
            font=("Segoe UI", 8),
            fg=COLOR_CAFE_OSCURO,
            bg=COLOR_BLANCO_HUESO
        )
        lbl_ruta_log.pack(side="left", padx=10)

        self.txt_logs = scrolledtext.ScrolledText(
            self.tab_logs,
            font=("Consolas", 9),
            bg=COLOR_TERMINAL_BG,
            fg=COLOR_TERMINAL_FG,
            insertbackground=COLOR_TERMINAL_FG,
            wrap="none"
        )
        self.txt_logs.pack(fill="both", expand=True, padx=10, pady=5)
        self._gui_leer_archivo_log()

    def _gui_leer_archivo_log(self) -> None:
        self.txt_logs.delete("1.0", tk.END)
        if os.path.exists(ARCHIVO_LOG):
            try:
                with open(ARCHIVO_LOG, "r", encoding="utf-8") as f:
                    contenido = f.read()
                    self.txt_logs.insert(tk.END, contenido)
                    self.txt_logs.see(tk.END)
            except Exception as err:
                self.txt_logs.insert(tk.END, f"Error al abrir log: {err}")
        else:
            self.txt_logs.insert(tk.END, "El archivo 'software_fj.log' aún no existe.")

    def _cargar_datos_iniciales_si_vacio(self) -> None:
        """Carga datos de demostración si la memoria está vacía para facilidad de uso inmediato."""
        if not self.sistema.servicios:
            s1 = ReservaSala("SAL-101", "Sala Ejecutiva Innovación", 45000.0, 20, True, True)
            s2 = AlquilerEquipo("EQP-201", "Workstation Móvil Dell Precision", 25000.0, "Dell Precision 5570", "Cómputo", 300000.0)
            s3 = AsesoriaEspecializada("ASE-301", "Consultoría Arquitectura Cloud AWS", 80000.0, "Cloud Computing", "SENIOR")
            self.sistema.registrar_servicio(s1)
            self.sistema.registrar_servicio(s2)
            self.sistema.registrar_servicio(s3)

        if not self.sistema.clientes:
            self.sistema.registrar_cliente("1098765432", "Pablo Andrés Plata Marín", "pablo.plata@unad.edu.co", "3158901234")
            self.sistema.registrar_cliente("1012345678", "María Fernanda Gómez", "maria.gomez@empresa.com", "3207654321")

    def _refrescar_todas_las_tablas(self) -> None:
        self._refrescar_tabla_clientes()
        self._refrescar_tabla_servicios()
        self._refrescar_tabla_reservas()
        self._actualizar_combos_reserva()


# ==================================================================================================
# 13. MENÚ INTERACTIVO POR CONSOLA (MODO TEXTO)
# ==================================================================================================
def menu_interactivo_consola(sistema: SistemaGestionFJ) -> None:
    """Proporciona una interfaz alternativa por consola para operar interactivamente el sistema."""
    while True:
        print("\n" + "=" * 60)
        print("          SOFTWARE FJ - MENÚ PRINCIPAL (CONSOLA)")
        print("=" * 60)
        print("  1. Ejecutar Simulación Oficial (12 Operaciones)")
        print("  2. Registrar Nuevo Cliente")
        print("  3. Registrar Nuevo Servicio Especializado")
        print("  4. Crear Nueva Reserva")
        print("  5. Confirmar Reserva")
        print("  6. Cancelar Reserva")
        print("  7. Procesar y Facturar Reserva")
        print("  8. Listar Clientes, Servicios y Reservas")
        print("  9. Ver Contenido del Archivo de Logs (software_fj.log)")
        print("  0. Salir del Sistema")
        print("=" * 60)

        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            ejecutar_simulacion_requerida(sistema)

        elif opcion == "2":
            print("\n--- REGISTRO DE CLIENTE ---")
            try:
                identificacion = input("Número de Identificación (6-12 dígitos): ").strip()
                nombre = input("Nombre Completo: ").strip()
                correo = input("Correo Electrónico: ").strip()
                telefono = input("Teléfono Móvil (10 dígitos): ").strip()
                cli = sistema.registrar_cliente(identificacion, nombre, correo, telefono)
                print(f"[OK] Cliente registrado exitosamente: {cli.nombre_completo}")
            except SoftwareFJError as err:
                print(f"[ERROR CONTROLADO] {err}")

        elif opcion == "3":
            print("\n--- REGISTRO DE SERVICIO ESPECIALIZADO ---")
            print("1. Reserva de Sala")
            print("2. Alquiler de Equipo")
            print("3. Asesoría Especializada")
            tipo = input("Seleccione el tipo de servicio (1-3): ").strip()
            try:
                cod = input("Código de Servicio (ej. SAL-02, EQP-02, ASE-02): ").strip()
                nom = input("Nombre Descriptivo: ").strip()
                tarifa = float(input("Tarifa Base por Hora (COP): ").strip())

                if tipo == "1":
                    cap = int(input("Capacidad de Personas: ").strip())
                    proy = input("¿Incluye Proyector? (s/n): ").strip().lower() == "s"
                    srv = ReservaSala(cod, nom, tarifa, cap, proy)
                elif tipo == "2":
                    mod = input("Marca y Modelo: ").strip()
                    tipo_eq = input("Tipo de Equipo: ").strip()
                    dep = float(input("Depósito en Garantía (COP): ").strip())
                    srv = AlquilerEquipo(cod, nom, tarifa, mod, tipo_eq, dep)
                elif tipo == "3":
                    area = input("Área de Especialidad: ").strip()
                    nivel = input("Nivel del Consultor (JUNIOR / SENIOR / MASTER): ").strip().upper()
                    srv = AsesoriaEspecializada(cod, nom, tarifa, area, nivel)
                else:
                    print("[AVISO] Tipo de servicio no reconocido.")
                    continue

                sistema.registrar_servicio(srv)
                print(f"[OK] Servicio {srv.id_servicio} registrado correctamente.")
            except (SoftwareFJError, ValueError) as err:
                print(f"[ERROR CONTROLADO] {err}")

        elif opcion == "4":
            print("\n--- CREACIÓN DE RESERVA ---")
            try:
                cod_res = input("Código para la Reserva (ej. RES-100): ").strip()
                cc_cli = input("Identificación del Cliente: ").strip()
                id_srv = input("Código del Servicio a Reservar: ").strip()
                dur = float(input("Duración estimada en Horas: ").strip())
                obs = input("Observaciones adicionales: ").strip()
                res = sistema.crear_reserva(cod_res, cc_cli, id_srv, dur, obs)
                print(f"[OK] Reserva creada con éxito. Código: {res.id_entidad} | Estado: {res.estado.value}")
            except (SoftwareFJError, ValueError) as err:
                print(f"[ERROR CONTROLADO] {err}")

        elif opcion == "5":
            print("\n--- CONFIRMACIÓN DE RESERVA ---")
            cod_res = input("Ingrese el Código de la Reserva a Confirmar: ").strip()
            try:
                sistema.confirmar_reserva(cod_res)
                print(f"[OK] La reserva {cod_res} fue confirmada exitosamente.")
            except SoftwareFJError as err:
                print(f"[ERROR CONTROLADO] {err}")

        elif opcion == "6":
            print("\n--- CANCELACIÓN DE RESERVA ---")
            cod_res = input("Ingrese el Código de la Reserva a Cancelar: ").strip()
            motivo = input("Motivo de la cancelación: ").strip()
            try:
                sistema.cancelar_reserva(cod_res, motivo)
                print(f"[OK] La reserva {cod_res} fue cancelada correctamente.")
            except SoftwareFJError as err:
                print(f"[ERROR CONTROLADO] {err}")

        elif opcion == "7":
            print("\n--- PROCESAR Y FACTURAR RESERVA ---")
            cod_res = input("Ingrese el Código de la Reserva Confirmada: ").strip()
            try:
                desc_str = input("Porcentaje de descuento comercial (ej. 0.05 para 5%, o Enter para 0): ").strip()
                desc = float(desc_str) if desc_str else 0.0
                cupon = input("Cupón promocional (opcional, ej. FJ2026 / ESTUDIANTE o Enter): ").strip() or None
                seguro_str = input("Seguro adicional en COP (o Enter para 0): ").strip()
                seguro = float(seguro_str) if seguro_str else 0.0

                factura = sistema.procesar_reserva(
                    codigo_reserva=cod_res,
                    porcentaje_descuento=desc,
                    cupon=cupon,
                    seguro_adicional=seguro
                )
                print(f"\n[OK] Reserva {cod_res} liquidada exitosamente:")
                for k, v in factura.items():
                    print(f"     - {k}: ${v:,.2f}" if isinstance(valor := v, float) else f"     - {k}: {valor}")
            except (SoftwareFJError, ValueError) as err:
                print(f"[ERROR CONTROLADO] {err}")

        elif opcion == "8":
            print("\n================== CLIENTES REGISTRADOS ==================")
            for c in sistema.listar_clientes():
                print("  * " + c)

            print("\n================== SERVICIOS ACTIVOS ==================")
            for s in sistema.listar_servicios():
                print("  * " + s)

            print("\n================== RESERVAS EN EL SISTEMA ==================")
            for r in sistema.listar_reservas():
                print("  * " + r)

        elif opcion == "9":
            print("\n================== REGISTRO DE AUDITORÍA (LOGS) ==================")
            if os.path.exists(ARCHIVO_LOG):
                try:
                    with open(ARCHIVO_LOG, "r", encoding="utf-8") as f:
                        lineas = f.readlines()
                        ultimas = lineas[-25:] if len(lineas) > 25 else lineas
                        print(f"Mostrando últimas {len(ultimas)} entradas del log:\n")
                        for linea in ultimas:
                            print(linea.strip())
                except Exception as e:
                    print(f"[ERROR] No se pudo leer el archivo de log: {e}")
            else:
                print("El archivo de logs aún no ha sido creado.")

        elif opcion == "0":
            print("\nGracias por utilizar el sistema de Software FJ. ¡Hasta pronto!")
            logger.info("=== CIERRE DE SESIÓN DEL SISTEMA SOFTWARE FJ ===")
            break

        else:
            print("[AVISO] Opción no válida. Por favor digite una opción entre 0 y 9.")


# ==================================================================================================
# 14. PUNTO DE ENTRADA PRINCIPAL (MAIN)
# ==================================================================================================
if __name__ == "__main__":
    sistema_central = SistemaGestionFJ()

    # Si se ejecuta con el argumento --consola, inicia el menú de texto
    if "--consola" in sys.argv:
        ejecutar_simulacion_requerida(sistema_central)
        menu_interactivo_consola(sistema_central)
    else:
        # Por defecto inicia con la Interfaz Gráfica Tkinter (Ventana de Login)
        try:
            app_login = VentanaLogin(sistema_central)
            app_login.mainloop()
        except Exception as error_gui:
            logger.critical(f"Error fatal al inicializar interfaz gráfica Tkinter: {error_gui}")
            print(f"\n[ALERTA] No se pudo inicializar la interfaz gráfica ({error_gui}).")
            print("Iniciando automáticamente en modo Consola interactivo...\n")
            ejecutar_simulacion_requerida(sistema_central)
            menu_interactivo_consola(sistema_central)
