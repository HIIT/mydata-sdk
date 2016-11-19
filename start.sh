mkdir -p ./init-db
cp ./Account/doc/database/MyDataAccount-DBinit.sql ./init-db/
cp ./Account/doc/database/MyDataAccount-UserInit.sql ./init-db/
cp ./Operator_Components/doc/database/Operator_Components-DBinit.sql ./init-db/
cp ./Service_Components/doc/database/Service_Components-DBinit.sql ./init-db/
cp ./Service_Mockup/doc/database/Service_Mockup-DBinit.sql ./init-db/

docker-compose rm --force mysql-db                  # Clean db
docker volume rm mydatasdkbleedingedge_mysql-data   # Clean db
reset                                               # Reset terminal
docker-compose down -v --remove-orphans             # Clean out trash.
docker-compose up --build                           # Put the thing up and running

