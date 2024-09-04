import bcrypt from "bcrypt"
import jwt from 'jsonwebtoken';
import nodemailer from "nodemailer"

//password hashing
export async function hashPassword (password : string){
    return await bcrypt.hash(password, 12)
}

//send email




export const sendEmail = async (options : any ) => {
   
  const transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "a923b5c9d9b79e",
      pass: "1ca8a9d5a665de",
    },
  });
  
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: options.email,
    subject: options.subject,
    text: options.text,
    html: `<a href=${options.message}> ${options.message} </a> `
  };

  await transporter.sendMail(mailOptions);

  transporter.verify((error, success) => {
    if (error) {
      console.error("SMTP Verification Error:", error);
    } else {
      console.log("SMTP Server is ready to take messages");
    }
  });
  
};




//custom api response
export class ApiResponse<T> {
    public statusCode: number;
    public data: T;
    public message: string;
    public success: boolean;
  
    constructor(statusCode: number, data: T, message: string = "success") {
      this.statusCode = statusCode;
      this.data = data;
      this.message = message;
      this.success = statusCode < 400;
    }
  }
  
  
  export const generateToken = (userId : string, userName : string, role : string  ) => {
      return jwt.sign({ userId, userName, role }, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
      });
  };
  
  export const setTokenCookie = (res : any, token : string) => {
      res.cookie("accessToken", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
      });
  };
  