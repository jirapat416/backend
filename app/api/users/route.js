import { Client } from 'pg';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();
const client = new Client({
  connectionString: process.env.DATABASE_URL,
});
client.connect();

export async function GET() {
    try {
          const result = await client.query('SELECT * FROM tbl_users ORDER BY ID ASC');
          return new Response(JSON.stringify(result.rows), {
              status: 200,
              headers: { 'Access-Control-allow-Origin': '*', "Content-Type": "application/json" },
          });
    } catch (error) {
      
          return new Response(JSON.stringify({ error: "Internal Server Error" }), {
              status: 500,
              headers: {'Access-Control-allow-Origin': '*', "Content-Type": "application/json" },
          });
    }
  }

  export async function POST(request) {
    try {
    const { firstname, lastname, username, password } = await request.json();
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    const res = await client.query('INSERT INTO tbl_users (firstname, lastname, username, password) VALUES ($1, $2, $3, $4) RETURNING *', [firstname, lastname, username, hashedPassword]);
    return new Response(JSON.stringify(res.rows[0]), {
    status: 201,
    headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
    });
    } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
    status: 500,
    headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
    });
    }
    }

    export async function PUT(request) {
      try {
      const { id, firstname, lastname } = await request.json();
      const res = await client.query('UPDATE tbl_users SET firstname = $1, lastname = $2 WHERE id = $3 RETURNING *', [firstname, lastname, id]);
      if (res.rows.length === 0) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 404,
      headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
      });
      }
      return new Response(JSON.stringify(res.rows[0]), {
      status: 200,
      headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
      });
      } catch (error) {
      console.error(error);
      return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
      });
      }
      }

      export async function DELETE(request) {
        try {
        const { id } = await request.json();
        const res = await client.query('DELETE FROM tbl_users WHERE id = $1 RETURNING *', [id]);
        if (res.rows.length === 0) {
        return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
        });
        }
        return new Response(JSON.stringify(res.rows[0]), {
        status: 200,
        headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
        });
        } catch (error) {
        console.error(error);
        return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        headers: { 'Access-Control-allow-Origin': '*', 'Content-Type': 'application/json' },
        });
        }
        }

        export async function hashPassword(password) {
          const saltRounds = 10;
          const hashedPassword = await bcrypt.hash(password, saltRounds);
          return hashedPassword;
        }
        
        export async function comparePassword(password, hashedPassword) {
          const match = await bcrypt.compare(password, hashedPassword);
          return match;
        }