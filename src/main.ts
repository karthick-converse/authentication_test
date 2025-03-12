import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as path from 'path';  // Correct import for 'path' module
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';


async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);



  // Swagger configuration
  const options = new DocumentBuilder()
    .setTitle('My Auth Api')                   // API Title
    .setDescription('My API description') // API Description
    .setVersion('1.0')                    // API Version
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('api-docs', app, document); // Swagger UI endpoint
   // Enable the global validation pipe
   app.useGlobalPipes(new ValidationPipe({
    transform: true, // Automatically transforms payloads to DTOs
    whitelist: true, // Automatically strips properties that do not have decorators
    forbidNonWhitelisted: true, // Throws an error if non-whitelisted properties are present
  }));
  app.setViewEngine('ejs'); 
  

  // Set the views folder (relative to the root directory)
  app.setBaseViewsDir(path.join(__dirname,'..','views'));

  app.useStaticAssets(path.join(__dirname, '..', 'uploads'), { prefix: '/uploads' });

  

  // Set the public folder for static assets like CSS, images, JS
  app.useStaticAssets(path.join(__dirname, '..', 'public'));
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
