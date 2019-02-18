/*********************************************************************************************

sp_ForensicsInvestigations : v01.01 (2019-01-19)

(C) 2019-2019, Dobereiner Miller

Feedback: mailto:dobereiner.miller@gmail.com

Updates: https://github.com/miudos


License: 

	sp_ForensicsInvestigations is free to download and use for personal, educational, and internal 

	corporate purposes, provided that this header is preserved. Redistribution or sale 

	of sp_ForensicsInvestigations, in whole or in part, is prohibited without the author's express 

	written consent.

*********************************************************************************************/
create or alter proc [dbo].[sp_ForensicsInvestigations]
(
      -- Provide the path and the name of the backup file to make a Forensics Investigation for those files
	    -- IF Empty, by the default the procedure will analyze the current LDF log file.
declare            @from_backup_file                       varchar           (512)='',
			--Each element in this list must be one of the valid transaction names. Names must be delimited by comma.
			--White spaces are allowed
                   @transactions_name_list                 varchar           (400)

)
as
begin

	set @transactions_name_list = ''

	set nocount on
												    
	declare @sizeinBytesSatusBitA                   tinyint           = 1
	declare @sizeInBytesSatusBitB                   tinyint           = 1
	declare @sizeInBytesFDataLength                 tinyint           = 2
	declare @numberOfColumns						            smallint
	declare @sizeInBytesNullBitmap					        smallint
	declare @max_length                             smallint    
	declare @leaf_offset                            smallint    
	declare @leaf_null_bit                          smallint
	declare @offset_pos                             smallint          = 0
	declare @offset_pos_aux                         smallint          = 0
	declare @rawDataContent0                        varbinary         (8000)
	declare @rawDataContent1                        varbinary         (8000)
	declare @rawDataContent2                        varbinary         (8000)
	declare @nullBitmask                            varbinary         (8000)
	declare @nullBitmask_aux                        varbinary         (8000)
	declare @data_aux                               varbinary         (8000)
	declare @transaction_id                         varchar           (14)
	declare @transaction_name                       varchar           (50)
	declare @transaction_sid                        varchar           (256)
	declare @tsql_columns                           Nvarchar          (max)
	declare @tsql_values                            Nvarchar          (max)  = ''
	declare @overall_progress_status                Nvarchar          (500)  = ''
	declare @operation                              Nvarchar          (31)   = ''
	declare @context                                Nvarchar          (31)   = ''
	declare @collation_name                         sysname	    
	declare @type__name                             sysname
	declare @column_name                            sysname
	declare @object__name                           sysname           = 'current'
	declare @previous_object__name                  sysname           = 'previous'
	declare @count                                  int               = 0
	declare @rowid                                  int               = 0
	declare @count_aux                              int               = 0
	declare @sizeOfNullBitmapArray                  int 
	declare @fixedDataLenghtValue					          int
	declare @isValidBackup                          int
	declare @partition_column_id                    int		    
	declare @int                                    int
  declare @logid                                  bigint            = 0
	declare @totalRowsInLog                         bigint            = 0
	declare @bigInt                                 bigint
	declare @float                                  float
	declare @datetime                               datetime
												    
	declare @columnMappingTable					    
			as table	(	rowid				    int identity      (1,1),
							partition_column_id	    int,
							max_length			    smallint,
							collation_name		    sysname	          null,
							leaf_offset			    smallint,
							leaf_null_bit		    smallint,
							type__name              sysname,
							column_name             sysname
						)						    

	if OBJECT_ID('tempdb..#dbLogRead') is not null drop table #dbLogRead
	create table #dbLogRead
			      (	logid				            int identity      (1,1),
							transaction_id		      nvarchar	       (14),
							rowlog_content_0	      varbinary	      (8000),
							rowlog_content_1	      varbinary	      (8000),
							transaction_name        nvarchar          (33),
							transaction_sid         nvarchar          (256),
							object__name            sysname           null,
							operation               nvarchar          (31),
							context                 nvarchar          (31),
							index ix_logid          clustered         (logid),
							index idx_object__name  nonclustered      (object__name)
						)

	declare @dbLogDumpRead							    
			as table	(	logid				    int identity      (1,1),
							[Transaction ID]		nvarchar	      (14),
							[RowLog Contents 0]	    varbinary	      (8000),
							[RowLog Contents 1]	    varbinary	      (8000),
							[Transaction Name]      nvarchar          (33),
							[Transaction SID]       varbinary         (85),
							[PartitionId]           bigint,
							[Operation]             nvarchar          (31),
							[Context]               nvarchar          (31)
						)

	declare @dbLogXactStatus							    
			as table	(   rowid                   int identity      (1,1),
							[Transaction ID]        nvarchar          (14),
							[operation]             nvarchar          (31),
							index ix_tid            clustered         ([Transaction ID])
				        )

												    
	declare @tempResult							    
			as table	(   rowid                   int identity      (1,1),
							[sid]                   nvarchar          (256),
							[Value]                 nvarchar          (max),
							[operation]             nvarchar          (31),
							[transaction_id]        nvarchar          (14)
				        )

	declare @resultIdTable
	        as table   (    rowid                   int
			           )

	declare @backupFileHeader
			as table	(   BackupName              nvarchar          (128),
							BackupDescription       nvarchar          (255),
							BackupType              smallint,
							ExpirationDate          datetime,
							Compressed              bit,
							Position                smallint,
							DeviceType              tinyint,
							UserName                nvarchar          (128),
							ServerName              nvarchar          (128),
							DatabaseName            nvarchar          (128),
							DatabaseVersion         int,
							DatabaseCreationDate    datetime,
							BackupSize              numeric           (20,0),
							FirstLSN                numeric           (25,0),
							LastLSN                 numeric           (25,0),
							CheckpointLSN           numeric           (25,0),
							DatabaseBackupLSN       numeric           (25,0),
							BackupStartDate         datetime,
							BackupFinishDate        datetime,
							SortOrder               smallint,
							[CodePage]              smallint,
							UnicodeLocaleId         int,
							UnicodeComparisonStyle  int,
							CompatibilityLevel      tinyint,
							SoftwareVendorId        int,
							SoftwareVersionMajor    int,
							SoftwareVersionMinor    int,
							SoftwareVersionBuild    int,
							MachineName             nvarchar          (128),
							Flags                   int,
							BindingId               uniqueidentifier,
							RecoveryForkId          uniqueidentifier,
							Collation               nvarchar          (128),
							FamilyGUID              uniqueidentifier,
							HasBulkLoggedData       bit,
							IsSnapshot              bit,
							IsReadOnly              bit,
							IsSingleUser            bit,
							HasBackupChecksums      bit,
							IsDamaged               bit,
							BeginsLogChain          bit,
							HasIncompleteMetaData   bit,
							IsForceOffline          bit,
							IsCopyOnly              bit,
							FirstRecoveryForkID     uniqueidentifier,
							ForkPointLSN            numeric           (25,0),
							RecoveryModel           nvarchar          (60),
							DifferentialBaseLSN     numeric           (25,0),
							DifferentialBaseGUID    uniqueidentifier,
							BackupTypeDescription   nvarchar          (60),
							BackupSetGUID           uniqueidentifier,
							CompressedBackupSize    bigint,
							Containment             tinyint,
							KeyAlgorithm            nvarchar          (32),
							EncryptorThumbprint     varbinary         (20),
							EncryptorType           nvarchar          (32)
	                    )

	if (@from_backup_file != '')
		begin
			SET @tsql_values = N'RESTORE HEADERONLY FROM DISK = ''' + @from_backup_file + ''''

			INSERT @backupFileHeader
			EXEC (@tsql_values)

			if ((SELECT 1 FROM @backupFileHeader where BackupType in (2,5)) is null)
				begin
					RAISERROR ('For backup files, please provide a Log or Differenctial backup only', 16, 1);
					return
				end

			set @tsql_values = ''
			
			insert into @dbLogDumpRead
			SELECT
				[Transaction ID], [RowLog Contents 0], [RowLog Contents 1], [Transaction Name], [Transaction SID], [PartitionId], [Operation], [Context]
			FROM
				sys.fn_dump_dblog
				(
					NULL, NULL, N'DISK', 1, @from_backup_file,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT,
					DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT
				)

			;with dbLogRead
			as
			(
				select
					distinct [Transaction SID] TSID, [Transaction ID] TID, [Transaction Name] TN
				from
					@dbLogDumpRead
				where
					[Transaction SID] is not null
			)
			insert into #dbLogRead
			select
				[Transaction ID], [RowLog Contents 0], [RowLog Contents 1], dbLogRead.TN [Transaction Name], SUSER_SNAME (dbLogRead.TSID) [Transaction SID], OBJECT_NAME (p.object_id) AllocUnitName, [Operation], [Context]
			from @dbLogDumpRead
			inner join dbLogRead on
				dbLogRead.TID = [Transaction ID]
			inner join sys.partitions p on
				p.partition_id = PartitionId
		end
	else
		begin
			;with dbLogRead
			as
			(
				select
					distinct [Transaction SID] TSID, [Transaction ID] TID, [Transaction Name] TN
				from
					sys.fn_dblog (null, null)
				where
					[Transaction SID] is not null
			)
			insert into #dbLogRead
			select
				[Transaction ID], [RowLog Contents 0], [RowLog Contents 1], dbLogRead.TN [Transaction Name], SUSER_SNAME (dbLogRead.TSID) [Transaction SID], AllocUnitName, Operation, Context
			from sys.fn_dblog (null, null)
			left join dbLogRead on
				dbLogRead.TID = [Transaction ID]
		end
		
	delete from #dbLogRead where object__name = 'Unknown Alloc Unit'

	select @logid = MIN (logid) from #dbLogRead

	select @totalRowsInLog = count(*) from #dbLogRead

	select @overall_progress_status = 'Parsing ' + cast (@totalRowsInLog as varchar(max)) + ' registers from the log - ' + convert (varchar(23), getdate(), 121)
	RAISERROR (@overall_progress_status, 0, 1) WITH NOWAIT


	while (@logid is not null)
		begin
			select
			    @transaction_id   = transaction_id,
				@rawDataContent0  = rowlog_content_0,
				@transaction_name = transaction_name,
				@transaction_sid  = transaction_sid,
				@object__name     = object__name,
				@operation        = operation,
				@context          = context
			from #dbLogRead
			where
				logid = @logid
			
			set @fixedDataLenghtValue =  cast (reverse (substring (@rawDataContent0, (@sizeinBytesSatusBitA + @sizeInBytesSatusBitB) + 1, @sizeInBytesFDataLength)) as binary(2))
			set @numberOfColumns = cast (CONVERT (BINARY (2), REVERSE (SUBSTRING (@rawDataContent0, @fixedDataLenghtValue + 1, 2))) as smallint)
			set @sizeInBytesNullBitmap = ceiling (@numberOfColumns / 8.0)
			
			if DATALENGTH (@rawDataContent0) = 0 or @sizeInBytesNullBitmap <= 0
			begin
				select @logid = MIN (logid) from #dbLogRead where logid > @logid
				continue
			end

			set @nullBitmask = SUBSTRING (@rawDataContent0, CONVERT (int, @fixedDataLenghtValue ) + 3, @sizeInBytesNullBitmap)
			
			set @sizeOfNullBitmapArray = @numberOfColumns
			
			set @count_aux = 1
			set @count = 0
			set @nullBitmask_aux = 0x00

			delete from @resultIdTable

			while (@sizeOfNullBitmapArray > 0)
			begin

				if (@count % 8 = 0)
				begin
					set @nullBitmask_aux = substring (@nullBitmask, @count_aux, 1)
		
					set @count_aux +=1
				end

				set @count +=1
				if (@nullBitmask_aux % 2) = 1
					insert into @resultIdTable values (@count)
    
				set @nullBitmask_aux = convert (int, (@nullBitmask_aux / 2))
				set @sizeOfNullBitmapArray -=1
			end

			--if (@previous_object__name != @object__name)
			--begin
			    delete from @columnMappingTable
				insert into @columnMappingTable
				select
					ipc.partition_column_id,
					ipc.max_length,
					ipc.collation_name,
					ipc.leaf_offset,
					ipc.leaf_null_bit,
					st.name,
					c.name
				from sys.system_internals_partition_columns ipc
				inner join sys.partitions p on
					ipc.partition_id = p.partition_id
				inner join sys.types st on
					st.system_type_id = ipc.system_type_id
				inner join sys.columns c on
					c.object_id = p.object_id
					and c.column_id = ipc.partition_column_id
				where
					p.object_id = object_id (@object__name)
					and st.user_type_id < 256

				set @previous_object__name = @object__name

				if (@transaction_name = 'INSERT' or @context = 'LOP_INSERT_ROWS' or @operation = 'LOP_INSERT_ROWS')
					set @tsql_columns = 'INSERT INTO ' + @object__name + ' ( ' + (SELECT
										STUFF ( (SELECT ', ' + column_name
												  FROM @columnMappingTable
												  FOR XML PATH ('')), 1, 1, ''
											  )) + ')'
				else if @context IN ('LCX_MARK_AS_GHOST', 'LCX_HEAP') AND @operation in ('LOP_DELETE_ROWS') 
					set @tsql_columns = 'DELETE - Under object: ' + @object__name + ' | ' +  'INSERT INTO ' + @object__name + ' ( ' + (SELECT
										STUFF ( (SELECT ', ' + column_name
												  FROM @columnMappingTable
												  FOR XML PATH ('')), 1, 1, ''
											  )) + ')'
				else if @transaction_name = 'DROPOBJ'
					set @tsql_columns = 'Object Droped: ' + @object__name
				else if substring(@transaction_name, 1, 6) = 'CREATE'
					set @tsql_columns = 'CREATE OBJECT: ' + @object__name
			--end

			select @rowid = min (rowid) from @columnMappingTable

			set @tsql_values = ''

			while (@rowid is not null)
			begin			   
				select
					@partition_column_id = partition_column_id,
					@max_length          = max_length,
					@collation_name      = collation_name,
					@leaf_offset         = leaf_offset,
					@leaf_null_bit       = leaf_null_bit,
					@type__name          = lower (type__name),
					@column_name         = column_name
				from @columnMappingTable
				where
					rowid = @rowid

				set @offset_pos = @leaf_offset

				if (@max_length > 0)
    				set @data_aux = substring (@rawDataContent0, @leaf_offset+1, @max_length)

				if ( @partition_column_id in (select rowId from @resultIdTable))
				begin
					set @tsql_values += 'NULL, '
				end
				else if (@collation_name is null)
					begin
						set @data_aux = convert (varbinary, reverse (@data_aux))
						if (@type__name = 'int')
							begin
								set @int = @data_aux
								set @tsql_values += CONVERT (VARCHAR (MAX), @int) + ', '
							end
						else if (@type__name = 'bigint')
							begin
								set @bigint = @data_aux
								set @tsql_values += CONVERT (VARCHAR (MAX), @bigint) + ', '
							end
						else if (@type__name = 'float')
							begin
								set @float = RTRIM (LTRIM (STR (CONVERT (FLOAT ,SIGN (CAST (CONVERT (VARBINARY (8), @data_aux) AS BIGINT)) * 
										(1.0 + (CAST (CONVERT (VARBINARY (8), @data_aux) AS BIGINT) & 0x000FFFFFFFFFFFFF) * POWER (CAST (2 AS FLOAT), -52)) * POWER (CAST (2 AS FLOAT),
										((CAST (CONVERT (VARBINARY (8), @data_aux) AS BIGINT) & 0x7ff0000000000000) / EXP (52 * LOG (2))-1023))),53,LEN (@data_aux))))
								set @tsql_values += CONVERT (VARCHAR (MAX), @float) + ', '
							end
						else if (@type__name = 'datetime')
							begin
								set @datetime =  CONVERT (DATETIME, CONVERT (VARBINARY(8) ,@data_aux), 121)
								set @tsql_values += quotename (CONVERT (VARCHAR (23), @datetime, 121), '''') + ', '
							end
					end
				else
					begin
						if (@type__name = 'char')
							set @tsql_values += QUOTENAME (CONVERT (VARCHAR (MAX), @data_aux), '''') + ', '
						else if (@type__name = 'nchar')
							set @tsql_values += QUOTENAME (CONVERT (NVARCHAR (MAX), @data_aux), '''') + ', '
					end
				select @rowid = min (rowid) from @columnMappingTable where rowid > @rowid
			end

			if (@tsql_columns like 'INSERT%')
				if NULLIF (LEN (LTRIM (RTRIM (@tsql_values)))-1,-1) is not null
					set @tsql_values = ' VALUES (' + LEFT (@tsql_values, NULLIF (LEN (@tsql_values)-1,-1)) + ')'
				else
				begin
					set @tsql_columns = null
					set @tsql_values = ''
				end
			else
				set @tsql_values = LEFT (@tsql_values, isnull (NULLIF (LEN (@tsql_values)-1,-1), ''))
			
			select @operation = operation from @dbLogXactStatus where [Transaction ID] = @transaction_id

			insert into @tempResult values (@transaction_sid, @tsql_columns + @tsql_values, @operation, @transaction_id)
		
			select @logid = MIN (logid) from #dbLogRead where logid > @logid
		end
		delete from @tempResult where [value] is null

		if object_id('tempdb..#tempResult') is not null drop table #tempResult

		select * into #tempResult from @tempResult
		select * from #tempResult order by [Value] asc, operation asc
end
