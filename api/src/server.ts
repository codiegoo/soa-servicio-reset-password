import express from "express";
import cors from "cors";

import { env } from "./config/env.js";

import {
  requestPasswordRecovery
} from "./services/password-recovery.service.js";


const app = express();


app.use(
  cors({

    origin:
      env.frontendUrl,

  })
);


app.use(
  express.json()
);


app.get(
  "/api/health",
  (_req, res) => {

    res.json({

      success: true,

      message:
        "API funcionando correctamente",

    });

  }
);


app.post(
  "/api/auth/forgot-password",

  async (req, res) => {

    try {

      const {
        email
      } = req.body;


      /*
       * Validación básica.
       */

      if (
        typeof email !== "string" ||
        !email.trim()
      ) {

        return res.status(400).json({

          success: false,

          message:
            "El correo electrónico es obligatorio.",

        });

      }


      /*
       * Ejecutar recuperación.
       */

      await requestPasswordRecovery(
        email
      );


      /*
       * NO decimos si el correo existe.
       */

      return res.json({

        success: true,

        message:
          "Si el correo está registrado, recibirás instrucciones para recuperar tu contraseña.",

      });


    } catch (error) {

      console.error(
        "Error en recuperación de contraseña:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "No fue posible procesar la solicitud.",

      });

    }

  }
);


app.listen(
  env.port,

  () => {

    console.log(
      `API ejecutándose en http://localhost:${env.port}`
    );

  }
);