import winston from "winston";
import * as dotenv from "dotenv";
dotenv.config();

function loggerProd() {
  return winston.createLogger({
    transports: [
      new winston.transports.File({
        filename: "prod-error.log",
        level: "error",
      }),
    ],
  });
}

function loggerDev() {
  return winston.createLogger({
    transports: [
      new winston.transports.Console({
        format: winston.format.simple(),
      }),
      new winston.transports.File({
        filename: "error.log",
        level: "error",
      }),
      new winston.transports.File({
        filename: "warn.log",
        level: "warn",
      })
    ],
  });
}

let logger = null;
if (process.env.NODE_ENV === "PROD") {
  logger = loggerProd();
  logger.info("logger iniciado en producción");
} else {
  logger = loggerDev();
  logger.info("logger iniciado en desarrollo");
}

export default logger;