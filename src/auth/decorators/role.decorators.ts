import { SetMetadata } from "@nestjs/common";
import { Roles } from "../enums/role.enums";



export const Role_key="roles";

export const Role=(...role:Roles[])=>
    SetMetadata(Role_key,role)
