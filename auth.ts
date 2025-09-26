// src/auth.ts
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
import type { User } from '@/app/lib/definitions';
import { authConfig } from './auth.config';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

// Schema de validación con Zod
const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

// Función auxiliar para traer usuario por email
async function getUser(email: string): Promise<User | null> {
  try {
    const rows = await sql<User[]>`
      SELECT id, name, email, password
      FROM users
      WHERE email = ${email}
      LIMIT 1
    `;
    return rows.length > 0 ? rows[0] : null;
  } catch (err) {
    console.error('DB error', err);
    return null;
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      name: 'Credentials',
      async authorize(credentials) {
        // Validar credenciales con zod
        const parsedCredentials = credentialsSchema.safeParse(credentials);

        if (!parsedCredentials.success) {
          console.log('Invalid credentials schema');
          return null;
        }

        const { email, password } = parsedCredentials.data;
        const user = await getUser(email);
        if (!user) return null;

        const passwordsMatch = await bcrypt.compare(password, user.password);
        if (!passwordsMatch) return null;

        // Devolver objeto de usuario (sin password)
        return {
          id: user.id,
          name: user.name,
          email: user.email,
        };
      },
    }),
  ],
});
