import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { Roles } from "../enums/role.enums";

@Entity()
export class Auth {

    @PrimaryGeneratedColumn()
    id:number; 
    
    @Column({
        unique:true
    })
    name:string;

    @Column()
    password:string;

    @Column()
    email:string;
    
    @Column({
        type:'enum',
        enum:Roles,
        default:Roles.user
    })
    role:Roles;

    @Column({ nullable: true }) // Make otp field optional
   otp: string;

 @Column({ nullable: true, type: 'bigint' }) // Change otpExpires type to bigint
  otpExpires: Date;

  @Column({default:false})
  verified:boolean;
  @Column()
  profileImage:string;
}
