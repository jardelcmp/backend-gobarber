import path from 'path';
import crypto from 'crypto';
import multer from 'multer';

const tmp = path.resolve(__dirname, '..', '..', 'tmp');
export default {
    directory: tmp,
    // serve para armazenar os arquivos na propria aplicacao/maquina
    storage: multer.diskStorage({
        destination: tmp,
        filename(request, file, callback) {
            const fileHash = crypto.randomBytes(10).toString('HEX');
            const fileName = `${fileHash}-${file.originalname}`;
            return callback(null, fileName);
        },
    }),
};
