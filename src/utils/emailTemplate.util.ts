// src/utils/email-templates.ts
// export function getVerificationEmailTemplate(name: string, url: string) {
//   return {
//     subject: "Verify your email - AuthKit",
//     html: `
//       <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//         <h1>Hi ${name}!</h1>
//         <p>Thanks for signing up. Please verify your email:</p>
//         <a href="${url}"
//            style="display: inline-block;
//                   background: #4CAF50;
//                   color: white;
//                   padding: 14px 28px;
//                   text-decoration: none;
//                   border-radius: 5px;">
//           Verify Email
//         </a>
//         <p>Or copy: ${url}</p>
//         <p style="color: #999;">Expires in 1 hour.</p>
//       </div>
//     `,
//   };
// }

export function getVerificationEmailTemplate(name: string, url: string) {
  return {
    subject: "Verify your email - AuthKit",
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="color-scheme" content="light dark">
        <meta name="supported-color-schemes" content="light dark">
        <style>
          :root { color-scheme: light dark; supported-color-schemes: light dark; }
          body { margin: 0; padding: 0; background-color: #0a0a0a; font-family: -apple-system, system-ui, sans-serif; }
          .wrapper { width: 100%; table-layout: fixed; background-color: #0a0a0a; padding-bottom: 40px; }
          .main { max-width: 480px; margin: 40px auto; background-color: #111111; border: 1px solid #222; border-radius: 12px; padding: 40px; text-align: left; }
          h1 { color: #ffffff; font-size: 24px; font-weight: 700; margin-top: 0; }
          p { color: #a1a1aa; font-size: 16px; line-height: 1.6; margin: 20px 0; }
          .button { 
            display: inline-block; 
            background-color: #ffffff; 
            color: #000000 !important; 
            padding: 12px 24px; 
            text-decoration: none; 
            border-radius: 8px; 
            font-weight: 600; 
            font-size: 15px;
            width: 100%;
            text-align: center;
            box-sizing: border-box;
          }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #222; color: #52525b; font-size: 12px; }
          .link-fallback { color: #3b82f6; text-decoration: none; font-size: 13px; word-break: break-all; }
          
          /* Force Dark Mode on supporting clients */
          @media (prefers-color-scheme: dark) {
            body, .wrapper { background-color: #000000 !important; }
            .main { background-color: #0a0a0a !important; border-color: #262626 !important; }
          }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="main">
            <div style="margin-bottom: 30px; font-weight: 800; color: #fff; font-size: 22px;">
              AUTH<span style="color: #3b82f6;">KIT</span>
            </div>
            <h1>Verify your email</h1>
            <p>Hi ${name},<br>Click the button below to verify your email address and finish setting up your account.</p>
            
            <a href="${url}" class="button">Verify Email</a>
            
            <p style="font-size: 14px; color: #71717a;">
              If the button doesn't work, copy and paste this link:<br>
              <a href="${url}" class="link-fallback">${url}</a>
            </p>
            
            <div class="footer">
              This link expires in 1 hour. If you didn't request this, ignore this email.<br>
              &copy; 2026 AuthKit. 
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
  };
}

export function getPasswordResetEmailTemplate(name: string, url: string) {
  // return {
  //   subject: "Reset your password - AuthKit",
  //   html: `
  //     <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  //       <h1>Hi ${name}!</h1>
  //       <p>Reset your password:</p>
  //       <a href="${url}"
  //          style="display: inline-block;
  //                 background: #f44336;
  //                 color: white;
  //                 padding: 14px 28px;
  //                 text-decoration: none;
  //                 border-radius: 5px;">
  //         Reset Password
  //       </a>
  //       <p>Or copy: ${url}</p>
  //       <p style="color: #999;">Expires in 1 hour.</p>
  //     </div>
  //   `,
  // };
  return {
    subject: "Reset your password - AuthKit",
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="color-scheme" content="light dark">
        <meta name="supported-color-schemes" content="light dark">
        <style>
          :root { color-scheme: light dark; supported-color-schemes: light dark; }
          body { margin: 0; padding: 0; background-color: #0a0a0a; font-family: -apple-system, system-ui, sans-serif; }
          .wrapper { width: 100%; table-layout: fixed; background-color: #0a0a0a; padding-bottom: 40px; }
          .main { max-width: 480px; margin: 40px auto; background-color: #111111; border: 1px solid #222; border-radius: 12px; padding: 40px; text-align: left; }
          h1 { color: #ffffff; font-size: 24px; font-weight: 700; margin-top: 0; }
          p { color: #a1a1aa; font-size: 16px; line-height: 1.6; margin: 20px 0; }
          .button { 
            display: inline-block; 
            background-color: #ffffff; 
            color: #000000 !important; 
            padding: 12px 24px; 
            text-decoration: none; 
            border-radius: 8px; 
            font-weight: 600; 
            font-size: 15px;
            width: 100%;
            text-align: center;
            box-sizing: border-box;
          }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #222; color: #52525b; font-size: 12px; }
          .link-fallback { color: #3b82f6; text-decoration: none; font-size: 13px; word-break: break-all; }
          
          @media (prefers-color-scheme: dark) {
            body, .wrapper { background-color: #000000 !important; }
            .main { background-color: #0a0a0a !important; border-color: #262626 !important; }
          }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="main">
            <div style="margin-bottom: 30px; font-weight: 800; color: #fff; font-size: 22px;">
              AUTH<span style="color: #3b82f6;">KIT</span>
            </div>
            <h1>Reset your password</h1>
            <p>Hi ${name},<br>We received a request to reset your password. Click the button below to choose a new one.</p>
            
            <a href="${url}" class="button">Reset Password</a>
            
            <p style="font-size: 14px; color: #71717a;">
              If the button doesn't work, copy and paste this link:<br>
              <a href="${url}" class="link-fallback">${url}</a>
            </p>
            
            <div class="footer">
              This link expires in 30 minutes. If you did not make this request, you can safely ignore this email; your password will not be changed.<br>
              &copy; 2026 AuthKit. 
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
  };
}
