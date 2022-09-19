import mongoose from "mongoose";

const config = {
    mongoDB:{
        URL:`mongodb://localhost:27017`,
        options:{
            useNewUrlParser: true,
            useUnifiedTopology: true,
        }
    }
}

export const connectMongoDB = async () => {
  try {
    await mongoose.connect(config.mongoDB.URL, config.mongoDB.options);
    console.log("Connected Mongo DB");
  } catch (error) {
    console.log("Error en la conexión a mongoDB", error);
  }
};