import {
  promises as fs
} from "node:fs";

import path from "node:path";

import {
  randomBytes,
  createHash
} from "node:crypto";

import {
  sendPasswordResetEmail
} from "./email.service.js";


const DB_PATH = path.resolve(
  "data/db.json"
);


interface Usuario {

  id: number;

  nombre: string;

  correo: string;

  telefono: string;

  password_hash: string;

  id_rol: number;

  estado: string;

}


interface TokenRecuperacion {

  id: number;

  id_usuario: number;

  token: string;

  fecha_expiracion: string;

  usado: boolean;

}


interface Database {

  roles: unknown[];

  usuarios: Usuario[];

  tokens_recuperacion:
    TokenRecuperacion[];

}


async function readDatabase():
  Promise<Database> {

  const content =
    await fs.readFile(
      DB_PATH,
      "utf-8"
    );

  return JSON.parse(content);

}


async function writeDatabase(
  database: Database
): Promise<void> {

  await fs.writeFile(

    DB_PATH,

    JSON.stringify(
      database,
      null,
      2
    ),

    "utf-8"

  );

}


function hashToken(
  token: string
): string {

  return createHash("sha256")
    .update(token)
    .digest("hex");

}


export async function
requestPasswordRecovery(
  email: string
) {

  const database =
    await readDatabase();


  const normalizedEmail =
    email.trim().toLowerCase();


  const usuario =
    database.usuarios.find(
      user =>
        user.correo
          .trim()
          .toLowerCase() ===
        normalizedEmail
    );


  /*
   * IMPORTANTE:
   *
   * No revelamos si el correo
   * existe o no.
   */

  if (!usuario) {

    return;

  }


  /*
   * Invalidamos tokens anteriores
   * que todavía no hayan sido usados.
   */

  database.tokens_recuperacion =
    database.tokens_recuperacion.map(
      token => {

        if (
          token.id_usuario ===
            usuario.id &&
          !token.usado
        ) {

          return {

            ...token,

            usado: true,

          };

        }

        return token;

      }
    );


  /*
   * Generamos un token
   * criptográficamente seguro.
   *
   * 32 bytes = 256 bits.
   */

  const rawToken =
    randomBytes(32)
      .toString("hex");


  /*
   * Solamente guardamos
   * el HASH en nuestra BD.
   */

  const hashedToken =
    hashToken(rawToken);


  /*
   * El token expira
   * en una hora.
   */

  const expiration =
    new Date(
      Date.now() +
      60 * 60 * 1000
    );


  const nextId =
    database.tokens_recuperacion.length
      ? Math.max(
          ...database.tokens_recuperacion
            .map(token => token.id)
        ) + 1
      : 1;


  const recoveryToken:
    TokenRecuperacion = {

    id: nextId,

    id_usuario:
      usuario.id,

    token:
      hashedToken,

    fecha_expiracion:
      expiration.toISOString(),

    usado: false,

  };


  database.tokens_recuperacion.push(
    recoveryToken
  );


  await writeDatabase(
    database
  );


  /*
   * Enviamos el TOKEN REAL
   * por correo.
   *
   * La BD solamente contiene
   * el hash.
   */

  await sendPasswordResetEmail(

    usuario.correo,

    usuario.nombre,

    rawToken

  );

}